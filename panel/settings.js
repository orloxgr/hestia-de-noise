(() => {
    'use strict';
    document.getElementById('hdn-log-scan')?.addEventListener('submit', async event => {
        event.preventDefault();
        const form = event.currentTarget;
        const button = form.querySelector('button[type="submit"]');
        const progress = document.getElementById('hdn-analysis-progress');
        const original = button.textContent;
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 20000);
        button.disabled = true;
        button.textContent = 'Analyzing available logs…';
        progress.textContent = 'Review running. Unsaved rule edits stay on this page.';
        try {
            // Hestia's hidden input named "action" shadows form.action.
            // Read the attribute so the request cannot target [object HTMLInputElement].
            const response = await fetch(form.getAttribute('action') || location.href, {
                method: 'POST', body: new FormData(form), credentials: 'same-origin', signal: controller.signal
            });
            const page = new DOMParser().parseFromString(await response.text(), 'text/html');
            const error = page.getElementById('hdn-request-error');
            const output = page.getElementById('hdn-analysis-output');
            if (!response.ok) throw new Error(`Review failed: HTTP ${response.status}. ${error?.textContent.trim() || 'The panel did not return a successful response.'}`);
            if (error) throw new Error(error.textContent.trim() || 'The panel rejected the review.');
            if (!output) {
                const loginRedirect = response.redirected && /\/login(?:\/|$)/.test(new URL(response.url).pathname);
                throw new Error(loginRedirect ? 'Your Hestia session has expired. Sign in again and retry the review.' : 'Review failed: the panel returned an unexpected page without a report.');
            }
            // Replace only the escaped report fragment, preserving every rule
            // field and unsaved switch in the existing settings form.
            document.getElementById('hdn-analysis-output').replaceChildren(...[...output.childNodes].map(node => document.importNode(node, true)));
            progress.textContent = 'Review completed. Protection settings and unsaved rule edits are unchanged.';
        } catch (error) {
            progress.textContent = error.name === 'AbortError' ? 'Review timed out. Protection settings and rule edits are unchanged.' : error.message;
        } finally {
            clearTimeout(timeout);
            button.disabled = false;
            button.textContent = original;
        }
    });
    const presets = JSON.parse(document.getElementById('hdn-agent-presets').textContent);
    const probePresets = JSON.parse(document.getElementById('hdn-probe-presets').textContent);
    document.querySelectorAll('[data-hdn-probe-preset]').forEach(button => button.addEventListener('click', () => {
        const field = document.getElementById(button.dataset.hdnProbeField);
        const lines = field.value.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
        (probePresets[button.dataset.hdnProbePreset] || []).forEach(value => { if (!lines.includes(value)) lines.push(value); });
        field.value = lines.join('\n');
    }));
    document.getElementById('hdn-probe-domain')?.addEventListener('change', event => {
        document.querySelectorAll('[data-hdn-probe-domain]').forEach(panel => { panel.hidden = panel.dataset.hdnProbeDomain !== event.target.value; });
    });
    document.querySelectorAll('[data-hdn-preset]').forEach(button => button.addEventListener('click', () => {
        const field = document.getElementById(button.dataset.hdnAgentField);
        const lines = field.value.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
        (presets[button.dataset.hdnPreset] || []).forEach(agent => {
            if (!lines.some(line => line.toLowerCase() === agent.toLowerCase())) lines.push(agent);
        });
        field.value = lines.join('\n');
    }));
    const tabs = [...document.querySelectorAll('[data-hdn-tab]')];
    tabs.forEach(button => {
        button.addEventListener('click', () => {
            const save = document.getElementById('hdn-save');
            if (save) save.hidden = ['cron', 'domain-bans', 'wordpress'].includes(button.dataset.hdnTab);
            document.querySelectorAll('input[name="tab"]').forEach(input => { input.value = button.dataset.hdnTab; });
            if (button.dataset.hdnTab === 'wordpress' && document.getElementById('hdn-wordpress-status')?.dataset.loaded === 'false') {
                document.getElementById('hdn-wordpress-refresh')?.requestSubmit();
            }
        });
        button.addEventListener('keydown', event => {
            if (!['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return;
            event.preventDefault();
            const columns = getComputedStyle(button.parentElement).gridTemplateColumns.split(' ').length;
            const step = event.key === 'ArrowUp' ? -columns : event.key === 'ArrowDown' ? columns :
                event.key === 'ArrowLeft' ? -1 : 1;
            const index = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 :
                (tabs.indexOf(button) + step + tabs.length) % tabs.length;
            tabs[index].click();
        });
    });
    document.addEventListener('invalid', event => {
        const panel = event.target.closest('[role="tabpanel"]');
        if (panel?.hidden) document.getElementById(panel.getAttribute('aria-labelledby'))?.click();
    }, true);
    document.getElementById('hdn-select')?.addEventListener('click', () => {
        const boxes = [...document.querySelectorAll('.hdn-target')];
        const next = boxes.some(box => !box.checked);
        boxes.forEach(box => { box.checked = next; });
    });
})();
