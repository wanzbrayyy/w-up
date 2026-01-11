const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

const r2 = new S3Client({
    region: 'auto',
    endpoint: 'https://ec786e5c4cd0818807637b34da897d76.r2.cloudflarestorage.com',
    credentials: {
        accessKeyId: "b5d206db32cd483575bb7b5c45a1004c",
        secretAccessKey: "e6ac7126a347d1bc27553a47665d9abed6b2c4fbc10a1623cda43f3b27473af3",
    },
});

module.exports = { r2, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, getSignedUrl };