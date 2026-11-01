(() => {
    'use strict';
    const presets = JSON.parse(document.getElementById('hdn-rule-presets').textContent);
    const names = value => value.toLowerCase().split(/[\s,]+/).filter(Boolean).sort().join(',');
    const path = value => value.replace(/\/+$/, '') || '/';
    const domainSelect = document.getElementById('hdn-exception-domain');
    domainSelect?.addEventListener('change', () => {
        document.querySelectorAll('[data-hdn-exception-domain]').forEach(row => {
            row.hidden = row.dataset.hdnExceptionDomain !== domainSelect.value;
        });
    });
    document.querySelectorAll('[data-hdn-add]').forEach(button => button.addEventListener('click', () => {
        const module = button.dataset.hdnAdd;
        const list = document.getElementById('hdn-' + module + '-rows');
        const preset = (presets[module] || []).find(item => item.key === button.dataset.hdnRulePreset);
        const existing = [...list.querySelectorAll('.hdn-rule')];
        const field = (row, key) => row.querySelector('[name$="[' + key + ']"]');
        const match = (row, rule) => path(field(row, 'path').value) === path(rule.path) &&
            names(field(row, module === 'static' ? 'extensions' : 'parameters').value) ===
            names(rule[module === 'static' ? 'extensions' : 'parameters'].join(' '));
        const rules = preset ? preset.rules.filter(rule => !existing.some(row => match(row, rule))) : [null];
        const message = document.getElementById('hdn-' + module + '-message');
        if (existing.length + rules.length > 20) { message.textContent = 'Use at most 20 rules in this section.'; return; }
        if (!rules.length) { message.textContent = 'These rules already exist. Your settings were kept.'; return; }
        const template = document.getElementById('hdn-' + module + '-template');
        rules.forEach(rule => {
            const used = new Set([...document.querySelectorAll('.hdn-rule input[name$="[id]"]')].map(input => input.value));
            const base = rule ? rule.id : module;
            let number = 1, ident = rule ? base : base + '_1';
            while (used.has(ident)) ident = base + '_' + (++number);
            const indices = [...list.querySelectorAll('input[name$="[id]"]')].map(input => Number(input.name.match(/\[(\d+)\]/)?.[1] ?? -1));
            const next = Math.max(-1, ...indices) + 1;
            const fragment = template.content.cloneNode(true);
            fragment.querySelectorAll('[name]').forEach(input => { input.name = input.name.replace('__INDEX__', String(next)); });
            const row = fragment.querySelector('.hdn-rule');
            field(row, 'id').value = ident;
            if (rule) {
                for (const [key, value] of Object.entries(rule)) {
                    if (key === 'id' || key === 'targets') continue;
                    const input = field(row, key === 'action' ? 'rule_action' : key);
                    if (input.type === 'checkbox') input.checked = value;
                    else input.value = Array.isArray(value) ? value.join(input.tagName === 'TEXTAREA' ? '\n' : ' ') : value;
                }
            }
            list.appendChild(fragment);
        });
        message.textContent = 'Added ' + rules.length + ' rule(s). Review domains, then Save & Apply.';
    }));
    document.addEventListener('click', event => {
        const button = event.target.closest('[data-hdn-remove]');
        if (button) button.closest('.hdn-rule').remove();
    });
})();
