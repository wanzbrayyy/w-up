const {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} = require('@simplewebauthn/server');

// Validasi variabel lingkungan (environment variables)
if (!process.env.APP_HOSTNAME) {
    throw new Error('FATAL: APP_HOSTNAME is not defined in .env file.');
}
if (!process.env.APP_URL) {
    throw new Error('FATAL: APP_URL is not defined in .env file.');
}
if (!process.env.APP_NAME) {
    console.warn('Warning: APP_NAME is not defined. Using default "w upload".');
}

const rpID = 'wanzofc.site';
const rpName = 'w upload';
const origin = 'https://wanzofc.site';
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
            userID: user._id.toString(),
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

        if (verification.verified && verification.registrationInfo) {
            const { credentialPublicKey, credentialID, counter, transports } = verification.registrationInfo;
            const existingKey = user.passkeys.find(key => key.credentialID.equals(Buffer.from(credentialID)));
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
        }

        return verification;
    } catch (error) {
        console.error("Error verifying registration:", error);
        throw new Error(error.message || 'Passkey verification failed.');
    }
}

async function generatePasskeyLoginOptions(user) {
    try {
        const allowedCredentials = user.passkeys.map(key => ({
            id: key.credentialID,
            type: 'public-key',
            transports: key.transports,
        }));

        const options = await generateAuthenticationOptions({
            rpID: passkeyConfig.rpID,
            allowCredentials: allowedCredentials,
            userVerification: 'required',
        });

        user.currentChallenge = options.challenge;
        await user.save();

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