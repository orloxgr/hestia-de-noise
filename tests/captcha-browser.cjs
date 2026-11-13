// Optional real-browser proof against an explicitly prepared, owned test domain.
// Set HDN_CAPTCHA_TEST_URL, HDN_PUPPETEER_MODULE and HDN_BROWSER_EXECUTABLE.
const assert = require('node:assert/strict');
const puppeteer = require(process.env.HDN_PUPPETEER_MODULE || 'puppeteer-core');
const imageAnswer = require('./captcha-image-answer.cjs');
(async () => {
    const url = new URL(process.env.HDN_CAPTCHA_TEST_URL);
    const browser = await puppeteer.launch({executablePath: process.env.HDN_BROWSER_EXECUTABLE, headless: true,
        args: process.env.HDN_BROWSER_TEST_TLS === 'self-signed' ? ['--ignore-certificate-errors'] : []});
    try {
        const page = await browser.newPage(), errors = [];
        page.on('pageerror', error => errors.push(error.message));
        await page.setViewport({width:1280, height:850});
        await page.goto(url.href, {waitUntil:'networkidle0'});
        assert.equal(await page.$eval('h1', node => node.textContent), 'A quick check');
        assert.equal(await page.$$eval('script', nodes => nodes.length), 0);
        const first = await page.$eval('[name=challenge]', node => node.value);
        await Promise.all([page.waitForNavigation(), page.click('[name=refresh]')]);
        assert.notEqual(await page.$eval('[name=challenge]', node => node.value), first);
        await page.type('#answer', '999');
        await Promise.all([page.waitForNavigation(), page.click('.primary')]);
        assert.match(await page.$eval('.notice', node => node.textContent), /incorrect/);
        await page.setViewport({width:390, height:844});
        await page.setExtraHTTPHeaders({'Accept-Language':'el-GR,el;q=0.9'});
        // A direct navigation should be challenged, even after failed same-origin form submissions.
        await page.goto(url.href, {waitUntil:'networkidle0'});
        assert.equal(await page.$eval('h1', node => node.textContent), 'Ένας γρήγορος έλεγχος');
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
        async function finish() {
            while (await page.$('[name=challenge]')) {
                const answer = imageAnswer(await page.$eval('img', node => node.src));
                await page.$eval('#answer', node => { node.value=''; });
                await page.type('#answer', answer);
                await Promise.all([page.waitForNavigation(), page.click('.primary')]);
                // Wait past the completion document and any WordPress canonical redirect.
                await page.waitForFunction(() => document.querySelector('[name=log]') || document.querySelector('[name=challenge]'));
            }
            assert(await page.$('[name=log]'), 'Verification must reach the actual WordPress login');
        }
        await finish();
        if (process.env.HDN_CAPTCHA_ALIAS_TEST_URL) {
            await page.deleteCookie(...await page.cookies());
            await page.goto(process.env.HDN_CAPTCHA_ALIAS_TEST_URL, {waitUntil:'domcontentloaded'});
            await finish();
        }
        assert.deepEqual(errors, []);
        console.log('CAPTCHA desktop, mobile, refresh, wrong-answer and complete WordPress login browser flows passed.');
    } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
