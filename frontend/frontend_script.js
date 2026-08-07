import { Main } from "./parser/main.js";

window.addEventListener('DOMContentLoaded', () => {
    const peFileInput = document.querySelector('#pe-file-input');
    peFileInput.addEventListener('change', (event) => {
        const file = event.target.files[0];
        if (!file) {
            return;
        }

        const reader = new FileReader();
        reader.onload = (e) => {
            const data = e.target.result;
            Main(data);
        };
        reader.readAsBinaryString(file);
    });
});