(() => {
    'use strict';
    const presets = JSON.parse(document.getElementById('hdn-agent-presets').textContent);
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
            document.querySelectorAll('input[name="tab"]').forEach(input => { input.value = button.dataset.hdnTab; });
        });
        button.addEventListener('keydown', event => {
            if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
            event.preventDefault();
            const index = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 :
                (tabs.indexOf(button) + (event.key === 'ArrowLeft' ? -1 : 1) + tabs.length) % tabs.length;
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
