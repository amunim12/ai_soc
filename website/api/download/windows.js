// Vercel serverless function — /api/download/windows
// Redirects to the latest AI SOC Windows installer on GitHub Releases.
// Deploy this alongside your website; point your download button to /api/download/windows

const OWNER = 'amunim12';
const REPO  = 'ai_soc';

export default async function handler(req, res) {
  try {
    const apiRes = await fetch(
      `https://api.github.com/repos/${OWNER}/${REPO}/releases/latest`,
      {
        headers: {
          Accept: 'application/vnd.github+json',
          'User-Agent': 'ai-soc-download-redirect/1.0',
        },
      }
    );

    if (!apiRes.ok) {
      res.status(502).send(`GitHub API error: ${apiRes.status}`);
      return;
    }

    const release = await apiRes.json();
    const asset = release.assets?.find((a) => a.name.endsWith('.exe'));

    if (!asset) {
      res.status(404).send('No Windows installer found in the latest release.');
      return;
    }

    // Cache for 5 minutes so rapid clicks don't hammer GitHub API
    res.setHeader('Cache-Control', 's-maxage=300, stale-while-revalidate');
    res.redirect(302, asset.browser_download_url);
  } catch (err) {
    res.status(500).send(`Redirect failed: ${err.message}`);
  }
}
