const fs = require("fs");
const jose = require("jose");
const jwktopem = require("jwk-to-pem");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const cors = require("cors");
var express = require("express");
var router = express();
router.use(express.json());
router.use(cors());

router.get("/rotate/ec", async (req, res) => {
	const { publicKey, privateKey } = await jose.generateKeyPair("PS256");

	const privateJwk = await jose.exportJWK(privateKey);
	const publicJwk = await jose.exportJWK(publicKey);

	console.log("privateJwk: ", privateJwk);
	console.log("publicJwk: ", publicJwk);

	fs.writeFileSync(
		"./public_keys_ec.json",
		JSON.stringify(publicJwk, null, "  ")
	);
	fs.writeFileSync(
		"./private_keys_ec.json",
		JSON.stringify(privateJwk, null, "  ")
	);

	res.send("EC Key Rotated!!");
});

router.get("/jwks/ec", async (req, res) => {
	const publicJwk = fs.readFileSync("./public_keys_ec.json");
	console.log(publicJwk.toString());

	res.send(publicJwk.toString());
});

router.get("/.well-known/keys.json", async (req, res) => {
	const publicJwk = fs.readFileSync("./public_keys_ec.json");
	console.log(publicJwk.toString());

	res.send(publicJwk.toString());
});

router.get("/token/ec", async (req, res) => {
	/**
	 * basically this is a demo to make a JWKS endpoint , but you have change your JWT token creator with JWKS endpoint
	 */
	const alg = "RS256";
	const privateJwk = fs.readFileSync("./private_keys_ec.json");
	const ecPrivateKey = await jose.importJWK(
		JSON.parse(privateJwk.toString()),
		"PS256"
	);

	const jwt = await new jose.SignJWT({ "urn:example:claim": true })
		.setProtectedHeader({ alg })
		.setIssuedAt()
		.setIssuer("urn:example:issuer")
		.setAudience("urn:example:audience")
		.setExpirationTime("2h")
		.sign(ecPrivateKey);

	res.send({ jwt });
});

router.post("/verify/ec", async (req, res) => {
	const { jwt } = req.body;
	const publicJwk = fs.readFileSync("./public_keys_ec.json");

	const ecPublicKey = await jose.importJWK(
		JSON.parse(publicJwk.toString()),
		"PS256"
	);

	const { payload, protectedHeader } = await jose.jwtVerify(
		jwt,
		ecPublicKey,
		{
			issuer: "urn:example:issuer",
			audience: "urn:example:audience",
		}
	);
	console.log("payload: ", payload);
	console.log("protectedHeader: ", protectedHeader);

	if (payload["iss"] === "urn:example:issuer") {
		res.send(true);
	}

	// try {
	// 	const decoded = jwt.verify(token, publicKey);
	// 	res.send(decoded);
	// } catch (e) {
	// 	res.send({ error: e });
	// }
});

const port = process.env.PORT || 3001;

router.get("*", (req, res) => res.end("Hello"));

router.listen(port, () => {
	console.log(`Server is running on ${port}`);
});
