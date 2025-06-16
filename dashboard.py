import dash
from dash import html, dcc, Input, Output, callback, dash_table
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from datetime import datetime
import os
from security_analyzer import run_all_checks, get_detailed_findings
from report_generator import create_pdf_report

# Initialize the Dash app
app = dash.Dash(__name__)

# Custom CSS styling
app.layout = html.Div([
    # Header Section
    html.Div([
        html.Div([
            html.H1("AWS Cloud Risk Analyzer",
                    style={'color': 'white', 'margin': '0', 'font-weight': 'bold'}),
            html.H3("by Bhavika Gupta",
                    style={'color': '#ecf0f1', 'margin': '5px 0 0 0', 'font-weight': 'normal'})
        ], style={'text-align': 'center', 'padding': '20px'})
    ], style={
        'background': 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
        'color': 'white',
        'margin-bottom': '30px',
        'border-radius': '10px',
        'box-shadow': '0 4px 6px rgba(0, 0, 0, 0.1)'
    }),

    # Control Panel
    html.Div([
        html.Div([
            html.Button("🔄 Refresh Scan", id="refresh-btn", n_clicks=0,
                        style={
                            'background-color': '#3498db',
                            'color': 'white',
                            'border': 'none',
                            'padding': '12px 24px',
                            'border-radius': '6px',
                            'cursor': 'pointer',
                            'font-size': '16px',
                            'margin-right': '10px'
                        }),
            html.Button("📄 Download PDF Report", id="download-btn", n_clicks=0,
                        style={
                            'background-color': '#e74c3c',
                            'color': 'white',
                            'border': 'none',
                            'padding': '12px 24px',
                            'border-radius': '6px',
                            'cursor': 'pointer',
                            'font-size': '16px'
                        }),
            dcc.Download(id="download-pdf")
        ], style={'text-align': 'center', 'margin-bottom': '30px'})
    ]),

    # Stats Cards
    html.Div(id="stats-cards", style={'margin-bottom': '30px'}),

    # Charts Section
    html.Div([
        html.Div([
            dcc.Graph(id="risk-pie-chart")
        ], style={'width': '48%', 'display': 'inline-block', 'margin-right': '4%'}),

        html.Div([
            dcc.Graph(id="service-bar-chart")
        ], style={'width': '48%', 'display': 'inline-block'})
    ], style={'margin-bottom': '30px'}),

    # Detailed Findings Table
    html.Div([
        html.H3("🔍 Detailed Security Findings",
                style={'color': '#2c3e50', 'margin-bottom': '20px'}),
        html.Div(id="findings-table")
    ], style={
        'background-color': 'white',
        'padding': '20px',
        'border-radius': '10px',
        'box-shadow': '0 2px 4px rgba(0, 0, 0, 0.1)'
    }),

    # Footer
    html.Div([
        html.P(id="last-updated",
               style={'text-align': 'center', 'color': '#7f8c8d', 'margin-top': '30px'})
    ])

], style={
    'font-family': 'Arial, sans-serif',
    'background-color': '#ecf0f1',
    'padding': '20px',
    'min-height': '100vh'
})


@callback(
    [Output('stats-cards', 'children'),
     Output('risk-pie-chart', 'figure'),
     Output('service-bar-chart', 'figure'),
     Output('findings-table', 'children'),
     Output('last-updated', 'children')],
    [Input('refresh-btn', 'n_clicks')]
)
def update_dashboard(n_clicks):
    # Get findings
    try:
        detailed_findings = get_detailed_findings()
    except Exception as e:
        # Handle case where AWS credentials might not be configured
        detailed_findings = [{
            'service': 'System',
            'issue_type': 'Configuration Error',
            'description': f'Unable to connect to AWS: {str(e)}',
            'severity': 'High',
            'resource': 'AWS Connection',
            'recommendation': 'Configure AWS credentials and ensure proper permissions'
        }]

    # Calculate statistics
    total_issues = len(detailed_findings)
    critical_issues = len([f for f in detailed_findings if f['severity'] == 'Critical'])
    high_issues = len([f for f in detailed_findings if f['severity'] == 'High'])
    medium_issues = len([f for f in detailed_findings if f['severity'] == 'Medium'])

    # Stats Cards
    stats_cards = html.Div([
        # Total Issues Card
        html.Div([
            html.H2(str(total_issues), style={'color': '#e74c3c', 'margin': '0', 'font-size': '48px'}),
            html.P("Total Issues", style={'margin': '5px 0', 'color': '#7f8c8d'})
        ], style={
            'background-color': 'white',
            'padding': '20px',
            'border-radius': '10px',
            'text-align': 'center',
            'box-shadow': '0 2px 4px rgba(0, 0, 0, 0.1)',
            'width': '22%',
            'display': 'inline-block',
            'margin-right': '4%'
        }),

        # Critical Issues Card
        html.Div([
            html.H2(str(critical_issues), style={'color': '#e74c3c', 'margin': '0', 'font-size': '48px'}),
            html.P("Critical", style={'margin': '5px 0', 'color': '#7f8c8d'})
        ], style={
            'background-color': 'white',
            'padding': '20px',
            'border-radius': '10px',
            'text-align': 'center',
            'box-shadow': '0 2px 4px rgba(0, 0, 0, 0.1)',
            'width': '22%',
            'display': 'inline-block',
            'margin-right': '4%'
        }),

        # High Issues Card
        html.Div([
            html.H2(str(high_issues), style={'color': '#f39c12', 'margin': '0', 'font-size': '48px'}),
            html.P("High", style={'margin': '5px 0', 'color': '#7f8c8d'})
        ], style={
            'background-color': 'white',
            'padding': '20px',
            'border-radius': '10px',
            'text-align': 'center',
            'box-shadow': '0 2px 4px rgba(0, 0, 0, 0.1)',
            'width': '22%',
            'display': 'inline-block',
            'margin-right': '4%'
        }),

        # Medium Issues Card
        html.Div([
            html.H2(str(medium_issues), style={'color': '#27ae60', 'margin': '0', 'font-size': '48px'}),
            html.P("Medium", style={'margin': '5px 0', 'color': '#7f8c8d'})
        ], style={
            'background-color': 'white',
            'padding': '20px',
            'border-radius': '10px',
            'text-align': 'center',
            'box-shadow': '0 2px 4px rgba(0, 0, 0, 0.1)',
            'width': '22%',
            'display': 'inline-block'
        })
    ])

    # Risk Distribution Pie Chart
    severity_counts = {'Critical': critical_issues, 'High': high_issues, 'Medium': medium_issues}
    # Filter out zero values for cleaner chart
    severity_counts = {k: v for k, v in severity_counts.items() if v > 0}

    if severity_counts:
        pie_fig = px.pie(
            values=list(severity_counts.values()),
            names=list(severity_counts.keys()),
            title="Risk Distribution by Severity",
            color_discrete_map={
                'Critical': '#e74c3c',
                'High': '#f39c12',
                'Medium': '#27ae60'
            }
        )
    else:
        pie_fig = px.pie(
            values=[1],
            names=['No Issues Found'],
            title="Risk Distribution by Severity",
            color_discrete_map={'No Issues Found': '#27ae60'}
        )

    pie_fig.update_layout(
        title_font_size=16,
        font=dict(size=12),
        showlegend=True
    )

    # Service Issues Bar Chart
    service_counts = {}
    for finding in detailed_findings:
        service = finding['service']
        service_counts[service] = service_counts.get(service, 0) + 1

    if service_counts:
        bar_fig = px.bar(
            x=list(service_counts.keys()),
            y=list(service_counts.values()),
            title="Issues by AWS Service",
            color=list(service_counts.values()),
            color_continuous_scale='Reds'
        )
    else:
        bar_fig = px.bar(
            x=['No Services'],
            y=[0],
            title="Issues by AWS Service"
        )

    bar_fig.update_layout(
        title_font_size=16,
        xaxis_title="AWS Service",
        yaxis_title="Number of Issues",
        font=dict(size=12)
    )

    # Findings Table
    if detailed_findings:
        df = pd.DataFrame(detailed_findings)

        table = dash_table.DataTable(
            data=df.to_dict('records'),
            columns=[
                {"name": "Service", "id": "service"},
                {"name": "Issue Type", "id": "issue_type"},
                {"name": "Description", "id": "description"},
                {"name": "Severity", "id": "severity"},
                {"name": "Resource", "id": "resource"}
            ],
            style_cell={
                'textAlign': 'left',
                'padding': '10px',
                'fontFamily': 'Arial',
                'overflow': 'hidden',
                'textOverflow': 'ellipsis',
                'maxWidth': 0
            },
            style_data_conditional=[
                {
                    'if': {'filter_query': '{severity} = Critical'},
                    'backgroundColor': '#fadbd8',
                    'color': 'black',
                },
                {
                    'if': {'filter_query': '{severity} = High'},
                    'backgroundColor': '#fdeaa7',
                    'color': 'black',
                },
                {
                    'if': {'filter_query': '{severity} = Medium'},
                    'backgroundColor': '#d5f4e6',
                    'color': 'black',
                }
            ],
            style_header={
                'backgroundColor': '#34495e',
                'color': 'white',
                'fontWeight': 'bold'
            },
            page_size=10,
            sort_action="native",
            filter_action="native",
            tooltip_data=[
                {
                    column: {'value': str(value), 'type': 'markdown'}
                    for column, value in row.items()
                } for row in df.to_dict('records')
            ],
            tooltip_duration=None
        )
    else:
        table = html.Div([
            html.P("No security findings to display.",
                   style={'text-align': 'center', 'color': '#7f8c8d', 'font-style': 'italic'})
        ])

    # Last updated timestamp
    last_updated = f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

    return stats_cards, pie_fig, bar_fig, table, last_updated


@callback(
    Output("download-pdf", "data"),
    Input("download-btn", "n_clicks"),
    prevent_initial_call=True
)
def download_report(n_clicks):
    if n_clicks and n_clicks > 0:
        # Ensure reports directory exists
        os.makedirs("reports", exist_ok=True)

        # Generate PDF report
        pdf_filename = f"reports/aws_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        create_pdf_report(pdf_filename)

        # Read the PDF file and return for download
        try:
            with open(pdf_filename, "rb") as f:
                pdf_data = f.read()

            return dcc.send_bytes(pdf_data, f"aws_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
        except Exception as e:
            print(f"Error downloading PDF: {e}")
            return None


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=8050)
