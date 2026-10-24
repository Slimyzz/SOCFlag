// Applies the saved theme before the page paints, so there is no flash.
try {
  const theme = localStorage.getItem('socflag:theme');
  if (theme === 'light' || theme === 'dark') document.documentElement.dataset.theme = theme;
} catch {}
