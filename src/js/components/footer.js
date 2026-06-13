export function loadFooter(selector = "#contact .footer_contact") {
    const footer = document.querySelector(selector);

    if (!footer) {
    console.warn(`Footer não encontrado: ${selector}`);
    return;
    }

    footer.innerHTML = `
    <div class="flex flex-wrap justify-center space-x-8">
        <a href="https://github.com/WendelTytan" target="_blank" rel="noopener noreferrer" class="transition-colors icons tooltip whitespace-nowrap" data-tooltip="GitHub">
            <svg xmlns="http://www.w3.org/2000/svg" class="icon-footer" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.403 5.403 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4"/><path d="M9 18c-4.51 2-5-2-7-2"/></svg>
            <span class="sr-only">GitHub</span>
        </a>

        <a href="https://www.linkedin.com/in/wendel-vinicius-25939b181/" target="_blank" rel="noopener noreferrer" class="transition-colors icons tooltip whitespace-nowrap" data-tooltip="LinkedIn">
            <svg xmlns="http://www.w3.org/2000/svg" class="icon-footer" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 8a6 6 0 0 1 6 6v7h-4v-7a2 2 0 0 0-2-2 2 2 0 0 0-2 2v7h-4v-7a6 6 0 0 1 6-6z"/><rect width="4" height="12" x="2" y="9"/><circle cx="4" cy="4" r="2"/></svg>
            <span class="sr-only">LinkedIn</span>
        </a>

        <a href="mailto:wendelvinicius@outlook.com.br" class="transition-colors icons tooltip whitespace-nowrap" data-tooltip="Email">
            <svg xmlns="http://www.w3.org/2000/svg" class="icon-footer" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>
            <span class="sr-only">Email</span>
        </a>

        <a href="https://wendeltytan.github.io/PortfoglioTytan/" class="transition-colors icons tooltip whitespace-nowrap" data-tooltip="Mais Sobre Mim">
            <svg xmlns="http://www.w3.org/2000/svg" class="icon-footer"
                viewBox="0 0 24 24" fill="none" stroke="currentColor"
                stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="2" y1="12" x2="22" y2="12"></line>
                <path d="M12 2a15.3 15.3 0 0 1 0 20"></path>
                <path d="M12 2a15.3 15.3 0 0 0 0 20"></path>
            </svg>
            <span class="sr-only">Mais Sobre Mim</span>
        </a>
    </div>

    <div class="text-lg font-bold texto-secundario text-center mt-6 mb-6">
        Quer me apoiar?
    </div>

    <div class="flex flex-wrap justify-center icons_footer">

        <a href="https://patreon.com/WendelTytan?utm_medium=unknown&utm_source=join_link&utm_campaign=creatorshare_creator&utm_content=copyLink" target="_blank" rel="noopener noreferrer" class="transition-colors icons inline-flex items-center hover:underline texto-terciario tooltip gap-2 whitespace-nowrap" data-tooltip="Patreon">
            <span class="icon-footer footer-pay bg-current inline-block"
                style="-webkit-mask: url('./src/images/etc/faviconPatreon.svg') center / contain no-repeat; mask: url('./src/images/etc/faviconPatreon.svg') center / contain no-repeat;">
            </span>
            <span>Patreon</span>
        </a>

        <a href="https://Ko-fi.com/wendetytan" target="_blank" rel="noopener noreferrer" class="transition-colors icons inline-flex items-center hover:underline texto-terciario tooltip gap-2 whitespace-nowrap" data-tooltip="Ko-Fi">
            <span class="icon-footer footer-pay bg-current inline-block"
                style="-webkit-mask: url('./src/images/etc/faviconKoFi.svg') center / contain no-repeat; mask: url('./src/images/etc/faviconKoFi.svg') center / contain no-repeat;">
            </span>
            <span>Ko-Fi</span>
        </a>

        <a href="https://www.buymeacoffee.com/WendelTytan" target="_blank" rel="noopener noreferrer" class="transition-colors icons inline-flex items-center hover:underline texto-terciario tooltip gap-2 whitespace-nowrap" data-tooltip="Buy-Me a Coffee">
            <span class="icon-footer footer-pay bg-current inline-block"
                style="-webkit-mask: url('./src/images/etc/faviconBuyMeaCoffee.svg') center / contain no-repeat; mask: url('./src/images/etc/faviconBuyMeaCoffee.svg') center / contain no-repeat;">
            </span>
            <span>Buy-Me a Coffee</span>
        </a>

        <a href="https://livepix.gg/wendeltytan" target="_blank" rel="noopener noreferrer" class="transition-colors icons inline-flex items-center hover:underline texto-terciario tooltip gap-2 whitespace-nowrap" data-tooltip="Live Pix">
            <span class="icon-footer footer-pay bg-current inline-block"
                style="-webkit-mask: url('./src/images/etc/faviconLivePix.png') center / contain no-repeat; mask: url('./src/images/etc/faviconLivePix.png') center / contain no-repeat;">
            </span>
            <span>Live Pix</span>
        </a>

        <a href="https://apoia.se/wendeltytan" target="_blank" rel="noopener noreferrer" class="transition-colors icons inline-flex items-center hover:underline texto-terciario tooltip gap-2 whitespace-nowrap" data-tooltip="Apoia-SE">
            <svg xmlns="http://www.w3.org/2000/svg" class="icon-footer footer-pay" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z"/>
            </svg>
            <span class="sr-only">Apoia-SE</span>
            Apoia-SE
        </a>

    </div>

    <div class="text-center text-sm mt-4 texto-primario">
        Wendel Tytan
    </div>

    <div class="text-center text-sm texto-primario">
        &copy; <span id="year"></span> Todos os direitos reservados.
    </div>
    `;

    const year = footer.querySelector("#year");
    if (year) {
        year.textContent = new Date().getFullYear();
    }
}

// TODO ajustar as tags que faltam na sincronia das novas tags tailwind
// TODO nome dos projetos está em placeholder
// TODO SKOOB bugado mais uma vez