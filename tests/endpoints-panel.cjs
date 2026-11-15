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
        await page.$eval('[data-hdn-append-endpoint="/wp-config.old"]',e=>e.closest('details').open=true);
        await page.click('[data-hdn-append-endpoint="/wp-config.old"]');
        await page.click('[data-hdn-append-endpoint="/wp-config.old"]');
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
        assert.deepEqual(result.appended,{name:'/wp-config.old',pattern:'/wp-config.old',enabled:false,ban:false,domains:['alice/one.test']});
        assert.deepEqual(result.saved,{enabled:true,ban:true,pattern:'^/saved\\.sql$'});
        assert.equal(result.valid,true);
        assert.equal((await page.$$('[data-hdn-append-endpoint="/wp-blog-header.php"], [data-hdn-endpoint404-path="/wp-blog-header.php"]')).length,0);
        assert.ok(await page.$eval('[data-hdn-endpoint-group]',e=>e.title.includes('existing files')));
        assert.ok(await page.$eval('[data-hdn-endpoint404-group]',e=>e.title.includes('first real 404')));
        await page.click('[data-hdn-select-endpoint404]');
        await page.click('[data-hdn-append-endpoint404]');
        assert.deepEqual(await page.$eval('#hdn-endpoint404-paths',e=>e.value.split('\n')),['/kept.php','/wp-config.old']);
        assert.equal(await page.$eval('[name="endpoint404_enabled"]',e=>e.checked),false);
        assert.equal(await page.$eval('[name="endpoint404_duration"]',e=>e.value),'2');
        assert.equal(await page.$eval('[name="endpoint404_unit"]',e=>e.value),'hours');
        await page.$eval('[data-hdn-endpoint-group]',e=>e.closest('details').open=true);
        await page.click('[data-hdn-endpoint-group]');
        await page.click('[data-hdn-endpoint-group]');
        assert.equal((await page.$$('#hdn-custom_endpoints-rows .hdn-rule')).length,3);
        assert.equal(await page.$eval('#hdn-custom_endpoints-rows .hdn-rule:last-child [name$="[type]"]',e=>e.value),'exact');
        await page.click('[data-hdn-endpoint404-group]');
        assert.deepEqual(await page.$eval('#hdn-endpoint404-paths',e=>e.value.split('\n')),['/kept.php','/wp-config.old','/wp-config.bak']);
        await page.click('[data-hdn-add="custom_endpoints"]');
        await page.$eval('#hdn-custom_endpoints-rows .hdn-rule:last-child [data-hdn-remove]',e=>e.click());
        assert.equal((await page.$$('#hdn-custom_endpoints-rows .hdn-rule')).length,3);
        for (const width of [1280,390]) {
            await page.setViewport({width,height:1200});
            const layout=await page.$eval('.hdn-endpoint-card',card=>{
                const field=card.querySelector('textarea').getBoundingClientRect();
                const buttons=[...card.querySelectorAll('.hdn-endpoint-actions button')].map(e=>e.getBoundingClientRect());
                return {overflow:document.documentElement.scrollWidth>window.innerWidth,
                    below:buttons.every(b=>b.top>=field.bottom),
                    contained:buttons.every(b=>b.left>=0 && b.right<=window.innerWidth)};
            });
            assert.deepEqual(layout,{overflow:false,below:true,contained:true});
        }
        if (process.env.HDN_SCREENSHOT) await page.screenshot({path:process.env.HDN_SCREENSHOT,fullPage:true});
        assert.deepEqual(errors,[]);
        if (process.argv[3]) fs.writeFileSync(process.argv[3],await page.$eval('#hdn-settings',e=>new URLSearchParams(new FormData(e)).toString()));
        console.log('Rendered endpoint append, deduplication, saved-state preservation, duration units, form association and remove: OK');
    } finally { await browser.close(); }
})().catch(error=>{console.error(error);process.exitCode=1;});
