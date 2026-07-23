window.onload = () => {
  window.ui = SwaggerUIBundle({
    url: 'openapi.yaml',
    dom_id: '#swagger',
    deepLinking: true,
    presets: [SwaggerUIBundle.presets.apis],
  });
};
