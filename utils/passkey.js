const {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} = require('@simplewebauthn/server');

if (!process.env.APP_HOSTNAME || !process.env.APP_URL) {
    throw new Error('FATAL: APP_HOSTNAME and APP_URL must be defined in .env file.');
}

const rpID = process.env.APP_HOSTNAME;
const rpName = process.env.APP_NAME || 'App Name';
const origin = process.env.APP_URL;

const passkeyConfig = { rpID, rpName, origin };

async function generatePasskeyRegistrationOptions(user) {
    try {
        const existingCredentials = user.passkeys.map(key => ({
            id: Buffer.from(key.credentialID).toString('base64url'),
            transports: key.transports,
        }));

        const options = await generateRegistrationOptions({
            rpName: passkeyConfig.rpName,
            rpID: passkeyConfig.rpID,
            userID: Buffer.from(user._id.toString(), 'utf8').toString('base64url'),
            userName: user.username,
            userDisplayName: user.username,
            attestationType: 'none',
            excludeCredentials: existingCredentials,
            authenticatorSelection: {
                residentKey: 'preferred',
                userVerification: 'preferred',
                requireResidentKey: false,
            },
        });

        user.currentChallenge = options.challenge;
        await user.save();

        return options;
    } catch (error) {
        console.error("Error generating registration options:", error);
        throw new Error('Could not prepare passkey registration.');
    }
}

async function verifyPasskeyRegistration(user, response) {
    try {
        const verification = await verifyRegistrationResponse({
            response,
            expectedChallenge: user.currentChallenge,
            expectedOrigin: passkeyConfig.origin,
            expectedRPID: passkeyConfig.rpID,
            requireUserVerification: false,
        });

        if (verification.verified) {
            const { registrationInfo } = verification;

            if (!registrationInfo) {
                throw new Error('Verification succeeded, but registrationInfo is null.');
            }

            let extractedID = registrationInfo.credentialID;
            let extractedKey = registrationInfo.credentialPublicKey;
            let extractedCounter = registrationInfo.counter;
            
            if (registrationInfo.credential) {
                extractedID = extractedID || registrationInfo.credential.id;
                extractedKey = extractedKey || registrationInfo.credential.publicKey;
                extractedCounter = extractedCounter || registrationInfo.credential.counter;
            }

            if (!extractedID && response.id) {
                extractedID = Buffer.from(response.id, 'base64url');
            }

            if (!extractedID || !extractedKey) {
                throw new Error('Internal Error: Credential ID or Public Key could not be extracted.');
            }

            const bufferID = Buffer.from(extractedID);
            const bufferKey = Buffer.from(extractedKey);

            const existingKey = user.passkeys.find(key => {
                const storedID = Buffer.isBuffer(key.credentialID) ? key.credentialID : Buffer.from(key.credentialID);
                return storedID.equals(bufferID);
            });

            if (existingKey) {
                throw new Error('This passkey is already registered.');
            }

            user.passkeys.push({
                credentialID: bufferID,
                credentialPublicKey: bufferKey,
                counter: extractedCounter,
                transports: registrationInfo.transports || [],
            });
            
            user.currentChallenge = undefined;
            await user.save();
        } else {
            throw new Error('Passkey verification failed.');
        }

        return verification;
    } catch (error) {
        console.error("Error in verifyPasskeyRegistration:", error);
        throw error;
    }
}

async function generatePasskeyLoginOptions(user) {
    try {
        const allowedCredentials = user ? user.passkeys.map(key => ({
            id: Buffer.from(key.credentialID).toString('base64url'),
            type: 'public-key',
            transports: key.transports,
        })) : [];

        const options = await generateAuthenticationOptions({
            rpID: passkeyConfig.rpID,
            allowCredentials: allowedCredentials,
            userVerification: 'preferred',
        });

        if (user) {
            user.currentChallenge = options.challenge;
            await user.save();
        }

        return options;
    } catch (error) {
        console.error("Error generating login options:", error);
        throw new Error('Could not prepare passkey login.');
    }
}

async function verifyPasskeyLogin(user, response) {
    try {
        const credential = user.passkeys.find(key => {
            const storedID = Buffer.from(key.credentialID).toString('base64url');
            return storedID === response.id;
        });

        if (!credential) {
            throw new Error('Passkey not found on this account.');
        }

        const verification = await verifyAuthenticationResponse({
            response,
            expectedChallenge: user.currentChallenge,
            expectedOrigin: passkeyConfig.origin,
            expectedRPID: passkeyConfig.rpID,
            authenticator: {
                credentialID: credential.credentialID,
                credentialPublicKey: credential.credentialPublicKey,
                counter: credential.counter,
                transports: credential.transports,
            },
            requireUserVerification: false,
        });

        if (verification.verified) {
            credential.counter = verification.authenticationInfo.newCounter;
            user.currentChallenge = undefined;
            await user.save();
        }

        return verification;
    } catch (error) {
        console.error("Error verifying login:", error);
        throw new Error(error.message || 'Passkey login failed.');
    }
}

module.exports = {
    passkeyConfig,
    generatePasskeyRegistrationOptions,
    verifyPasskeyRegistration,
    generatePasskeyLoginOptions,
    verifyPasskeyLogin
};