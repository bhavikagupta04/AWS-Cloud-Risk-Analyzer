import dash
from dash import html, dcc
from security_analyzer import run_all_checks

app = dash.Dash(__name__)
findings = run_all_checks()

app.layout = html.Div([
    html.H1("AWS Security Findings"),
    dcc.Textarea(
        value="\n".join(findings),
        style={'width': '100%', 'height': 400},
    )
])

if __name__ == '__main__':
    app.run(debug=True)
