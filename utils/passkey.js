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
const rpName = process.env.APP_NAME || 'w upload';
const origin = process.env.APP_URL;

const passkeyConfig = {
    rpID,
    rpName,
    origin,
};

async function generatePasskeyRegistrationOptions(user) {
    try {
        const existingCredentials = user.passkeys.map(key => ({
            id: key.credentialID,
            transports: key.transports,
        }));

        const options = await generateRegistrationOptions({
            rpName: passkeyConfig.rpName,
            rpID: passkeyConfig.rpID,
            userID: Buffer.from(user._id.toString(), 'utf8'),
            userName: user.username,
            userDisplayName: user.username,
            attestationType: 'none',
            excludeCredentials: existingCredentials,
            authenticatorSelection: {
                residentKey: 'required',
                userVerification: 'required',
                requireResidentKey: true,
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
            requireUserVerification: true,
        });

        if (verification.verified) {
            if (!verification.registrationInfo) {
                throw new Error('Verification succeeded, but registration information was missing.');
            }

            const { credentialPublicKey, credentialID, counter, transports } = verification.registrationInfo;

            if (!credentialID || !credentialPublicKey) {
                throw new Error('Internal Error: Credential data is missing after successful verification.');
            }

            const existingKey = user.passkeys.find(key => key.credentialID.equals(credentialID));
            if (existingKey) {
                throw new Error('This passkey is already registered.');
            }

            user.passkeys.push({
                credentialID: Buffer.from(credentialID),
                credentialPublicKey: Buffer.from(credentialPublicKey),
                counter,
                transports: transports || [],
            });
            
            user.currentChallenge = undefined;
            await user.save();
        } else {
            throw new Error('Passkey verification failed. Signature may be invalid or challenge mismatched.');
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
            id: key.credentialID,
            type: 'public-key',
            transports: key.transports,
        })) : undefined;

        const options = await generateAuthenticationOptions({
            rpID: passkeyConfig.rpID,
            allowCredentials: allowedCredentials,
            userVerification: 'required',
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
        const credential = user.passkeys.find(key => key.credentialID.equals(Buffer.from(response.rawId, 'base64')));
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
            requireUserVerification: true,
        });

        if (verification.verified) {
            const { newCounter } = verification.authenticationInfo;
            credential.counter = newCounter;
            
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