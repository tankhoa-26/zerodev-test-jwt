const fs = require("fs");
const jose = require("node-jose");
const jwktopem = require("jwk-to-pem");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const cors = require("cors");
var express = require("express");
var router = express();
router.use(express.json());
router.use(cors());
//deploy this in prod server....

/**
 * where "ec and rsa" are algorithms `https://your-domain/rotate/rsa` is for making keys by rotating everytime
 * https://your-domain/jwks/rsa this endpoint returns JWKS endpoint
 * https://your-domain/token/rsa this endpoint returns JWT token which is integrated with JWKS endpoint
 * https://your-domain/verify/rsa use to verify token in a post request
 */

// This endpoint will rotate your Keys
router.get("/rotate/ec", async (req, res) => {
  const keyStore = jose.JWK.createKeyStore();
  keyStore
    .generate("EC", "P-256", {
      alg: "ES256",
      use: "sig",
      x: "drUef3Fq_k496CUnMHWcwLeL8X6-z03Tg20tBlIQ1v4",
      y: "0BTWRnwr5Sgo7iw3gpe-UO_vldShnvPDnrG80UUA5VA",
      d: "0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk",
    })
    .then((result) => {
      fs.writeFileSync(
        "keys_ec.json",
        JSON.stringify(keyStore.toJSON(true), null, "  ")
      );
      console.log("keyStore", keyStore);
      console.log("result", result);
    });
  res.send("EC Key Rotated");
});

router.get("/rotate/rsa", async (req, res) => {
  const keyStore = jose.JWK.createKeyStore();
  keyStore
    .generate("RSA", 2048, { alg: "RS256", use: "sig" })
    .then((result) => {
      fs.writeFileSync(
        "keys_rsa.json",
        JSON.stringify(keyStore.toJSON(true), null, "  ")
      );
    });
  res.send("RSA Key Rotated");
});

// router.get("/.well-known/keys.json", async (req, res) => {
router.get("/jwks/rsa", async (req, res) => {
  const ks = fs.readFileSync("keys_ec.json");
  const keyStore = await jose.JWK.asKeyStore(ks.toString());
  res.send(keyStore.toJSON());
});

router.get("/.well-known/keys.json", async (req, res) => {
  const ks = fs.readFileSync("keys_rsa.json");
  const keyStore = await jose.JWK.asKeyStore(ks.toString());

  res.send(keyStore.toJSON());
});

router.get("/token/ec", async (req, res) => {
  /**
   * basically this is a demo to make a JWKS endpoint , but you have change your JWT token creator with JWKS endpoint
   */
  const ks = fs.readFileSync("keys_ec.json"); //change this with your JWKS endpoint https://your-domain/jwks/rsa by using api call or you can use like default
  const keyStore = await jose.JWK.asKeyStore(ks.toString());
  const [key] = keyStore.all({ use: "sig" });

  const payload = JSON.stringify({
    sub: "123",
    aud: "urn:zerodev:client",
  });
  // add below logic with your login token
  const token = await jose.JWS.createSign(
    { alg: "ES256", format: "compact" },
    key
  )
    .update(payload, "utf8")
    .final();
  res.send({ token });
});

// router.get("/token/rsa/:userID", async (req, res) => {
//   const { userID } = req.params;
//   const ks = fs.readFileSync("keys_rsa.json");
//   const keyStore = await jose.JWK.asKeyStore(ks.toString());
//   const [key] = keyStore.all({ use: "sig" });
//   console.log("key", key);
//   const opt = { compact: true, jwk: key, fields: { typ: "jwt" } };
//   const payload = JSON.stringify({
//     sub: "123",
//     aud: "urn:zerodev:client",
//   });
//   const token = await jose.JWS.createSign(opt, key).update(payload).final();
//   res.send({ token });
// });

router.get("/token/rsa/:userID", async (req, res) => {
  const { userID } = req.params;
  const ks = fs.readFileSync("keys_rsa.json");
  const keyStore = await jose.JWK.asKeyStore(ks.toString());
  const [key] = keyStore.all({ use: "sig" });

  const opt = { compact: true, jwk: key, fields: { typ: "jwt" } };
  const payload = JSON.stringify({
    sub: "123",
    aud: "urn:zerodev:client",
    userID,
    timestamp: Date.now(), // Include a timestamp for uniqueness
  });

  try {
    const token = await jose.JWS.createSign(opt, key).update(payload).final();
    res.send({ token });
  } catch (error) {
    console.error(error);
    res.status(500).send("Error generating token");
  }
});

router.post("/verify/rsa", async (req, res) => {
  const { token } = req.body;
  const { data } = await axios.get(
    "https://jwks-production.up.railway.app/jwks/rsa"
  );
  const [firstKey] = data.keys;
  const publicKey = jwktopem(firstKey);
  try {
    const decoded = jwt.verify(token, publicKey);
    res.send(decoded);
  } catch (e) {
    res.send({ error: e });
  }
});

router.post("/verify/ec", async (req, res) => {
  const { token } = req.body;
  const { data } = await axios.get(
    "https://jwks-production.up.railway.app/.well-known/keys.json"
  );
  const [firstKey] = data.keys;
  const publicKey = jwktopem(firstKey);
  try {
    const decoded = jwt.verify(token, publicKey);
    res.send(decoded);
  } catch (e) {
    res.send({ error: e });
  }
});
const port = process.env.PORT || 3000;

router.get("*", (req, res) => res.end("Hello"));

router.listen(port, () => {
  console.log(`Server is running on ${port}`);
});
