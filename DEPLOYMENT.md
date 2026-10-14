# Deploying PhishGuard AI

## What is deployed

Deploy the Flask API as a web service. The Chrome extension remains installed in the browser, but its `extension/config.js` file must point to the deployed API.

## Option 1: Render with Docker

1. Create a GitHub repository and push this project to it.
2. Create a Render account and choose **New > Blueprint**.
3. Select the GitHub repository. Render detects `render.yaml` and builds the `Dockerfile`.
4. Wait for the deployment to finish, then open:

   ```text
   https://YOUR-SERVICE.onrender.com/api/health
   ```

   A successful deployment returns JSON with `"status":"ok"`.

5. Edit `extension/config.js` and replace the local URL with:

   ```js
   self.PHISHGUARD_API_BASE = "https://YOUR-SERVICE.onrender.com/api";
   ```

6. Go to `chrome://extensions`, enable Developer mode, click **Reload** on PhishGuard AI, and test it.

## Important deployment notes

- The first startup can take longer because models may need to load or retrain.
- Use a paid instance or sufficient memory if the free service cannot train/load XGBoost models reliably.
- The API currently accepts requests without user authentication. It is suitable for a project demonstration, not unrestricted public production use.
- Do not use an HTTP deployment URL in the extension when browsing HTTPS websites. Use the HTTPS URL supplied by your hosting provider.

## Local development

Keep this in `extension/config.js` for local testing:

```js
self.PHISHGUARD_API_BASE = "http://127.0.0.1:5000/api";
```

Then run:

```powershell
python app.py
```
