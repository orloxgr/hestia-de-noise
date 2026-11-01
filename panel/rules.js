(() => {
    'use strict';
    document.querySelectorAll('[data-hdn-add]').forEach(button => button.addEventListener('click', () => {
        const module = button.dataset.hdnAdd;
        const list = document.getElementById('hdn-' + module + '-rows');
        if (list.querySelectorAll('.hdn-rule').length >= 20) return;
        const used = new Set([...document.querySelectorAll('.hdn-rule input[name$="[id]"]')].map(input => input.value));
        let id = 1;
        while (used.has(module + '_' + id)) id++;
        const indices = [...list.querySelectorAll('input[name$="[id]"]')].map(input => Number(input.name.match(/\[(\d+)\]/)?.[1] ?? -1));
        const next = Math.max(-1, ...indices) + 1;
        const template = document.getElementById('hdn-' + module + '-template');
        list.insertAdjacentHTML('beforeend', template.innerHTML.replaceAll('__INDEX__', String(next)).replaceAll('__ID__', module + '_' + id));
    }));
    document.addEventListener('click', event => {
        const button = event.target.closest('[data-hdn-remove]');
        if (button) button.closest('.hdn-rule').remove();
    });
})();
