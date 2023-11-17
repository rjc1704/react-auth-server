require("dotenv").config();

const express = require("express");
const jwt = require("jsonwebtoken");
const mysql = require("mysql");
const bcrypt = require("bcrypt");
const multer = require("multer");
const multerS3 = require("multer-s3");
const { S3Client } = require("@aws-sdk/client-s3");
const { v4: uuidv4 } = require("uuid");
const { fromEnv } = require("@aws-sdk/credential-providers");

const app = express();

const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PW,
  database: process.env.DB_NAME,
  port: 3306,
};

const SALT_ROUND = 10;
const SECRET_KEY = process.env.JWT_SECRET_KEY;
const PORT = 4000;

app.use(express.json());

const verifyTokenMiddleware = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader) {
    return res
      .status(401)
      .send("헤더에 authorization 정보가 존재하지 않습니다.");
  }

  const [, accessToken] = authHeader.split(" ");
  if (accessToken) {
    jwt.verify(accessToken, SECRET_KEY, (err, decodedToken) => {
      if (err) {
        if (err.name === "TokenExpiredError") {
          return res
            .status(401)
            .send("토큰이 만료되었습니다. 다시 로그인 해주세요.");
        }
        return res.status(401).send("토큰 검증에 실패했습니다.");
      }
      req.decodedToken = decodedToken;
    });
  }
  next();
};

// AWS S3 설정
const s3 = new S3Client({
  region: "ap-northeast-2",
  credentials: fromEnv(),
});

// Multer 및 multer-s3 설정
const upload = multer({
  storage: multerS3({
    s3: s3,
    bucket: process.env.BUCKET_NAME,
    acl: "public-read", // 업로드된 파일의 ACL 설정 (public-read는 모든 사용자에게 읽기 권한을 부여함)
    key: (req, file, cb) => {
      const imageKey = `${file.originalname}/${uuidv4()}.jpg`; // S3에 저장될 파일의 키
      cb(null, imageKey);
    },
  }),
});

// MySQL 연결 생성
const connection = mysql.createConnection(dbConfig);

// 연결 확인
connection.connect((err) => {
  if (err) {
    console.error("MySQL connection error:", err);
  } else {
    console.log("Connected to MySQL");
  }
});

app.get("/", (req, res) => {
  res.send("Hi! This is the JWT AUTHENTICATION SERVER!");
});

app.post("/register", (req, res) => {
  const { id, password, nickname } = req.body;
  if (!id || !password || !nickname) {
    return res
      .status(401)
      .json({ message: "아이디, 비밀번호, 닉네임은 필수값입니다." });
  }

  if (typeof id !== "string" || id.length < 4) {
    return res
      .status(401)
      .json({ message: "id는 4글자 이상의 문자열이어야 합니다." });
  }
  if (typeof password !== "string" || password.length < 4) {
    return res
      .status(401)
      .json({ message: "password는 4글자 이상의 문자열이어야 합니다." });
  }

  const checkDuplicateQuery = "SELECT * FROM users WHERE id = ?";
  connection.query(checkDuplicateQuery, [id], async (err, results) => {
    if (err) {
      console.error("MySQL query error:", err);
      return res.status(500).json({ message: "Internal Server Error" });
    }

    if (results.length > 0) {
      return res.status(409).json({ message: "이미 존재하는 유저 id입니다." });
    }
    // 비밀번호 해싱 및 솔팅
    const hashedPassword = await bcrypt.hash(password, SALT_ROUND);
    // 새로운 유저 추가
    const addUserQuery =
      "INSERT INTO users (id, password, nickname) VALUES (?, ?, ?)";
    connection.query(
      addUserQuery,
      [id, hashedPassword, nickname],
      (err, result) => {
        if (err) {
          console.error("MySQL query error:", err);
          return res.status(500).json({ message: "Internal Server Error" });
        }

        return res
          .status(201)
          .json({ message: "회원가입 완료", success: true });
      }
    );
  });
});

app.post("/login", (req, res) => {
  const { id, password } = req.body;
  const expiresIn = req.query.expiresIn;

  const tokenExpiresIn = expiresIn || "1h";

  if (typeof id !== "string" || id.length < 4) {
    return res
      .status(401)
      .json({ message: "id는 4글자 이상의 문자열이어야 합니다." });
  }
  if (typeof password !== "string" || password.length < 4) {
    return res
      .status(401)
      .json({ message: "password는 4글자 이상의 문자열이어야 합니다." });
  }

  // MySQL 쿼리를 사용하여 사용자 정보 조회
  const query = "SELECT * FROM users WHERE id = ?";

  connection.query(query, [id], (error, results) => {
    if (error) {
      return res
        .status(500)
        .json({ error: "사용자 정보 조회 중 오류가 발생했습니다." });
    }

    // 조회된 사용자 정보가 없으면 존재하지 않는 유저로 처리
    if (results.length === 0) {
      return res.status(401).json({ error: "존재하지 않는 유저입니다." });
    }

    const user = results[0];

    // 비밀번호 일치 여부 확인
    bcrypt.compare(password, user.password, (err, result) => {
      if (err) {
        return res
          .status(500)
          .json({ error: "비밀번호 비교 중 오류가 발생했습니다." });
      }

      if (!result) {
        return res.status(401).json({ error: "비밀번호가 일치하지 않습니다." });
      }

      // JWT 토큰 생성
      const accessToken = jwt.sign({ id }, SECRET_KEY, {
        expiresIn: tokenExpiresIn,
      });

      res.json({ accessToken, success: true });
    });
  });
});

app.get("/user", verifyTokenMiddleware, (req, res) => {
  // MySQL 쿼리를 사용하여 사용자 정보 조회
  const query = "SELECT * FROM users WHERE id = ?";
  const id = req.decodedToken.id;
  connection.query(query, [id], (error, results) => {
    if (error) {
      return res
        .status(500)
        .json({ error: "사용자 정보 조회 중 오류가 발생했습니다." });
    }

    // 조회된 사용자 정보가 없으면 존재하지 않는 유저로 처리
    if (results.length === 0) {
      return res.status(401).json({ error: "존재하지 않는 유저입니다." });
    }

    const user = results[0];

    return res.status(200).json({
      id: user.id,
      nickname: user.nickname,
      avatar: user.avatar,
      success: true,
    });
  });
});

app.post(
  "/upload",
  upload.single("avatar"),
  verifyTokenMiddleware,
  (req, res) => {
    try {
      if (req.file) {
        const imageUrl = req.file.location;
        const userId = req.decodedToken.id;

        // users 테이블의 avatar 열을 업데이트하는 SQL 쿼리
        const updateQuery = "UPDATE users SET avatar = ? WHERE id = ?";
        connection.query(updateQuery, [imageUrl, userId], (error) => {
          if (error) {
            console.error("프로필 이미지 업데이트 중 오류:", error);
            return res
              .status(500)
              .json({ error: "프로필 이미지 업데이트에 실패했습니다." });
          }

          return res.status(200).json({
            message: "이미지가 업로드되었습니다.",
            imageUrl: imageUrl,
            success: true,
          });
        });
      } else {
        return res
          .status(400)
          .json({ error: "파일이 제대로 업로드되지 않았습니다." });
      }
    } catch (error) {
      return res.status(401).send("토큰 검증에 실패했습니다.");
    }
  }
);

app.listen(PORT, () => {
  console.log("Listening on PORT", PORT);
});
