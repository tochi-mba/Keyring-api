const menuButton = document.querySelector('.menu-button');
const nav = document.querySelector('.site-nav');

const setMenu = (open, returnFocus = false) => {
  nav?.classList.toggle('open', open);
  menuButton?.setAttribute('aria-expanded', String(open));
  // Closing with the keyboard has to put focus somewhere sensible, or it falls back to the page.
  if (!open && returnFocus) menuButton?.focus();
};
menuButton?.addEventListener('click', () => setMenu(menuButton.getAttribute('aria-expanded') !== 'true'));
nav?.querySelectorAll('a').forEach(link => link.addEventListener('click', () => setMenu(false)));
document.addEventListener('keydown', event => {
  if (event.key === 'Escape') setMenu(false, true);
});

// While the menu is open it is the whole page as far as the keyboard is concerned.
document.addEventListener('focusin', event => {
  if (menuButton?.getAttribute('aria-expanded') !== 'true') return;
  if (nav?.contains(event.target) || event.target === menuButton) return;
  nav?.querySelector('a')?.focus();
});

const copyText = async text => {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
};
const copyStatus = document.getElementById('copy-status');
document.querySelectorAll('.copy-button').forEach(button => button.addEventListener('click', async () => {
  const label = button.textContent;
  const done = await copyText(button.dataset.copy);
  button.textContent = done ? 'Copied' : 'Copy failed';
  // The button changing its own text says nothing to a screen reader; this does.
  if (copyStatus) copyStatus.textContent = done ? 'Command copied to the clipboard' : 'Could not copy the command';
  setTimeout(() => { button.textContent = label; }, 1400);
}));

const year = document.getElementById('year');
if (year) year.textContent = String(new Date().getFullYear());
