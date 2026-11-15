'use strict';
// Optional rendered-browser check: PHP fixture output as argv[2].
const assert = require('node:assert/strict');
const fs = require('node:fs');
const puppeteer = require(process.env.HDN_PUPPETEER || 'puppeteer-core');
(async () => {
    const browser = await puppeteer.launch({executablePath:process.env.HDN_BROWSER,headless:true});
    try {
        const page=await browser.newPage(), errors=[];
        page.on('pageerror',error=>errors.push(error.message));
        await page.goto(require('node:url').pathToFileURL(process.argv[2]).href);
        assert.equal(await page.$eval('[name="custom_endpoints[0][duration]"]',e=>e.value),'2');
        assert.equal(await page.$eval('[name="custom_endpoints[0][duration_unit]"]',e=>e.value),'hours');
        await page.$eval('[data-hdn-append-endpoint="/backup.zip"]',e=>e.closest('details').open=true);
        await page.click('[data-hdn-append-endpoint="/backup.zip"]');
        await page.click('[data-hdn-append-endpoint="/backup.zip"]');
        const result=await page.evaluate(()=>{
            const rows=[...document.querySelectorAll('#hdn-custom_endpoints-rows .hdn-rule')];
            const field=(row,key)=>row.querySelector('[name$="['+key+']"]');
            const appended=rows[1];
            const domains=appended.querySelector('[name$="[targets][]"]');
            const saved=rows[0];
            return {count:rows.length,appended:{name:field(appended,'name').value,pattern:field(appended,'pattern').value,
                enabled:field(appended,'enabled').checked,ban:field(appended,'also_ban').checked,
                domains:[...domains.selectedOptions].map(o=>o.value)},
                saved:{enabled:field(saved,'enabled').checked,ban:field(saved,'also_ban').checked,pattern:field(saved,'pattern').value},
                valid:document.getElementById('hdn-settings').checkValidity(),
                encoded:new URLSearchParams(new FormData(document.getElementById('hdn-settings'))).toString()};
        });
        assert.equal(result.count,2);
        assert.deepEqual(result.appended,{name:'/backup.zip',pattern:'/backup.zip',enabled:false,ban:false,domains:['alice/one.test']});
        assert.deepEqual(result.saved,{enabled:true,ban:true,pattern:'^/saved\\.sql$'});
        assert.equal(result.valid,true);
        await page.click('[data-hdn-select-endpoint404]');
        await page.click('[data-hdn-append-endpoint404]');
        assert.deepEqual(await page.$eval('#hdn-endpoint404-paths',e=>e.value.split('\n')),['/kept.php','/backup.zip']);
        assert.equal(await page.$eval('[name="endpoint404_enabled"]',e=>e.checked),false);
        assert.equal(await page.$eval('[name="endpoint404_duration"]',e=>e.value),'2');
        assert.equal(await page.$eval('[name="endpoint404_unit"]',e=>e.value),'hours');
        await page.$eval('[data-hdn-endpoint-type="regex"]',e=>e.closest('details').open=true);
        await page.click('[data-hdn-endpoint-type="regex"]');
        await page.click('[data-hdn-endpoint-type="regex"]');
        assert.equal((await page.$$('#hdn-custom_endpoints-rows .hdn-rule')).length,3);
        assert.equal(await page.$eval('#hdn-custom_endpoints-rows .hdn-rule:last-child [name$="[type]"]',e=>e.value),'regex');
        await page.click('[data-hdn-endpoint404-group]');
        assert.deepEqual(await page.$eval('#hdn-endpoint404-paths',e=>e.value.split('\n')),['/kept.php','/backup.zip','/backup.rar']);
        await page.click('[data-hdn-add="custom_endpoints"]');
        await page.$eval('#hdn-custom_endpoints-rows .hdn-rule:last-child [data-hdn-remove]',e=>e.click());
        assert.equal((await page.$$('#hdn-custom_endpoints-rows .hdn-rule')).length,3);
        assert.deepEqual(errors,[]);
        if (process.argv[3]) fs.writeFileSync(process.argv[3],await page.$eval('#hdn-settings',e=>new URLSearchParams(new FormData(e)).toString()));
        console.log('Rendered endpoint append, deduplication, saved-state preservation, duration units, form association and remove: OK');
    } finally { await browser.close(); }
})().catch(error=>{console.error(error);process.exitCode=1;});
