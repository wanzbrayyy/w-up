const {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} = require('@simplewebauthn/server');

// Pastikan file .env memiliki variabel-variabel ini
const rpID = process.env.APP_HOSTNAME || 'localhost';
const rpName = process.env.APP_NAME || 'w upload';
const origin = process.env.APP_URL || `http://${rpID}:3000`;

const passkeyConfig = {
    rpID,
    rpName,
    origin,
};

async function generatePasskeyRegistrationOptions(user) {
    if (!user || !user._id || !user.username) {
        throw new Error("Invalid user object provided for passkey registration.");
    }
    
    try {
        const existingCredentials = user.passkeys.map(key => ({
            id: key.credentialID,
            transports: key.transports,
        }));

        const options = await generateRegistrationOptions({
            rpName: passkeyConfig.rpName,
            rpID: passkeyConfig.rpID,
            userID: user._id.toString(), // Wajib String
            userName: user.username,
            userDisplayName: user.username,
            attestationType: 'none',
            excludeCredentials: existingCredentials,
            authenticatorSelection: {
                residentKey: 'required',
                userVerification: 'required',
            },
        });

        user.currentChallenge = options.challenge;
        await user.save();

        return options;
    } catch (error) {
        console.error("Error in generateRegistrationOptions:", error);
        throw new Error('Could not prepare passkey registration.');
    }
}

async function verifyPasskeyRegistration(user, response) {
    if (!user || !user.currentChallenge) {
        throw new Error("User or challenge is missing for verification.");
    }

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
        console.error("Error in verifyPasskeyRegistration:", error);
        throw new Error(error.message || 'Passkey verification failed.');
    }
}

async function generatePasskeyLoginOptions(user) {
    if (!user) throw new Error("User not found.");

    try {
        // Jika user belum punya passkey, jangan generate apa-apa
        if (!user.passkeys || user.passkeys.length === 0) {
            return { error: 'No passkeys registered for this user.' };
        }

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
    if (!user || !user.passkeys || !response.rawId) {
        throw new Error("Invalid user or response for verification.");
    }
    
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