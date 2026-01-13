const express = require('express');
const router = express.Router();
const PublicRequest = require('../models/publicRequest');
const auth = require('../middleware/auth');

router.get('/', auth.checkAuthStatus, (req, res) => {
    res.render('request', { query: req.query });
});

router.post('/', async (req, res) => {
    try {
        const { requestType, contactEmail, url, description, botType } = req.body;

        if (!requestType || !contactEmail) {
            return res.redirect('/request?status=error&message=Request type and email are required.');
        }

        const newRequestData = {
            requestType,
            contactEmail,
            details: {}
        };

        if (requestType === 'scraper') {
            if (!url) {
                return res.redirect('/request?status=error&message=A valid URL is required for scraper requests.');
            }
            newRequestData.details.url = url;
        } else if (requestType === 'website') {
            if (!description || description.trim().length < 300) {
                return res.redirect('/request?status=error&message=Website description must be at least 300 characters.');
            }
            newRequestData.details.description = description;
        } else if (requestType === 'bot') {
            if (!botType) {
                return res.redirect('/request?status=error&message=Please select a bot type.');
            }
            if (!description || description.trim().length < 300) {
                return res.redirect('/request?status=error&message=Bot feature description must be at least 300 characters.');
            }
            newRequestData.details.botType = botType;
            newRequestData.details.description = description;
        } else {
            return res.redirect('/request?status=error&message=Invalid request type selected.');
        }

        const publicRequest = new PublicRequest(newRequestData);
        await publicRequest.save();

        res.redirect('/request?status=success');
    } catch (error) {
        console.error("Public request submission error:", error);
        res.redirect('/request?status=error&message=A server error occurred. Please try again.');
    }
});

module.exports = router;