// Run: node --test tests/panel-settings.test.cjs
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../panel/settings.js'), 'utf8');

async function submit({action = null, status = 200, panelError = null,
    report = true, redirected = false, url = 'https://panel.test/plugins/de-noise/', abort = false} = {}) {
    let handler;
    let request;
    let updated = false;
    let timerCleared = false;
    const button = {textContent: 'Analyze logs', disabled: false};
    const progress = {textContent: ''};
    const form = {
        // Real HTML forms expose a named input here instead of the URL string.
        action: {toString: () => '[object HTMLInputElement]'},
        getAttribute: name => { assert.equal(name, 'action'); return action; },
        querySelector: () => button,
        addEventListener: (name, callback) => { assert.equal(name, 'submit'); handler = callback; }
    };
    const nodes = {'hdn-log-scan': form, 'hdn-analysis-progress': progress,
        'hdn-agent-presets': {textContent: '{}'}, 'hdn-probe-presets': {textContent: '{}'},
        'hdn-analysis-output': {replaceChildren: (...children) => {updated = children.length === 1;}}};
    const context = {
        document: {getElementById: id => nodes[id], querySelectorAll: () => [],
            addEventListener() {}, importNode: node => node},
        location: {href: 'https://panel.test/plugins/de-noise/?tab=filters'},
        FormData: class {constructor(input) {assert.equal(input, form); this.fields = ['action', 'token', 'analysis_target'];}},
        AbortController, URL,
        setTimeout: () => 123,
        clearTimeout: id => {assert.equal(id, 123); timerCleared = true;},
        fetch: async (target, options) => {
            request = {target, options};
            if (abort) throw Object.assign(new Error('aborted'), {name: 'AbortError'});
            return {ok: status >= 200 && status < 300, status, redirected, url, text: async () => 'fixture'};
        },
        DOMParser: class {parseFromString() {return {getElementById: id =>
            id === 'hdn-request-error' ? (panelError === null ? null : {textContent: panelError}) :
                id === 'hdn-analysis-output' && report ? {childNodes: ['escaped report']} : null};}}
    };
    vm.runInNewContext(source, context);
    await handler({currentTarget: form, target: form, preventDefault() {}});
    assert.equal(button.disabled, false);
    assert.equal(button.textContent, 'Analyze logs');
    assert.equal(timerCleared, true);
    return {request, updated, message: progress.textContent};
}

test('named action input cannot shadow the current panel URL', async () => {
    const result = await submit();
    assert.equal(result.request.target, 'https://panel.test/plugins/de-noise/?tab=filters');
    assert.equal(result.request.options.method, 'POST');
    assert.equal(result.request.options.credentials, 'same-origin');
    assert.equal(result.request.options.body.fields.includes('token'), true);
    assert.equal(result.updated, true);
    assert.match(result.message, /Review completed/);
});
test('explicit action attribute is respected', async () => {
    assert.equal((await submit({action: '/plugins/de-noise/'})).request.target, '/plugins/de-noise/');
});
test('HTTP failures report their status without blaming the session', async () => {
    for (const status of [404, 500, 503]) {
        const result = await submit({status, report: false});
        assert.match(result.message, new RegExp(`HTTP ${status}`));
        assert.doesNotMatch(result.message, /session/i);
        assert.equal(result.updated, false);
    }
});
test('panel validation errors preserve the report', async () => {
    const result = await submit({panelError: 'Invalid CSRF token.'});
    assert.equal(result.message, 'Invalid CSRF token.');
    assert.equal(result.updated, false);
});
test('unexpected successful HTML is distinguished from login', async () => {
    const result = await submit({report: false});
    assert.match(result.message, /unexpected page/);
    assert.doesNotMatch(result.message, /session/i);
});
test('login redirect identifies an expired session', async () => {
    assert.match((await submit({report: false, redirected: true, url: 'https://panel.test/login/'})).message, /session has expired/);
});
test('unrelated redirects are not identified as session expiry', async () => {
    assert.match((await submit({report: false, redirected: true})).message, /unexpected page/);
});
test('timeouts restore controls without replacing the report', async () => {
    const result = await submit({abort: true});
    assert.match(result.message, /timed out/);
    assert.equal(result.updated, false);
});
