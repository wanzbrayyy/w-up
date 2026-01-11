const axios = require('axios');
const translationCache = new Map();

async function translateText(text, targetLang, sourceLang = 'auto') {
    if (!text) return '';
    
    const cacheKey = `${text}_${targetLang}_${sourceLang}`;
    if (translationCache.has(cacheKey)) {
        return translationCache.get(cacheKey);
    }

    try {
        const encodedText = encodeURIComponent(text);
        const url = `https://translate.google.com/translate_a/single?client=gtx&sl=${sourceLang}&tl=${targetLang}&dt=t&q=${encodedText}`;

        const response = await axios.get(url, {
            headers: { 'User-Agent': 'Mozilla/5.0' }
        });

        if (response.data && response.data[0]) {
            const translatedText = response.data[0].map(item => item[0]).join('');
            translationCache.set(cacheKey, translatedText);
            
            if (translationCache.size > 1000) translationCache.clear();
            
            return translatedText;
        }
        return text;
    } catch (error) {
        console.error('Translation Error:', error.message);
        return text;
    }
}

module.exports = { translateText };