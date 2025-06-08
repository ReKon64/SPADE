from core.imports import *

class Reporter:
    def __init__(self, template_path=None):
        if template_path and os.path.exists(template_path):
            with open(template_path, "r", encoding="utf-8") as f:
                template_str = f.read()
        else:
            # Fallback to default.html in templates folder
            default_path = os.path.join(os.path.dirname(__file__), "..", "templates", "default.html")
            with open(default_path, "r", encoding="utf-8") as f:
                template_str = f.read()
        self.template = Template(template_str)

    def generate_report(self, scan_data, output_file=None):
        """Generate HTML report from scan data"""
        # Calculate statistics
        total_open_ports = 0
        unique_services = set()
        for host in scan_data['hosts']:
            for port in host['ports']:
                if port['state'] == 'open':
                    total_open_ports += 1
                    if port.get('service', {}).get('name'):
                        unique_services.add(port['service']['name'])
        # Prepare template data
        template_data = {
            'hosts': scan_data['hosts'],
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_open_ports': total_open_ports,
            'unique_services': list(unique_services)
        }
        # Render template
        html_content = self.template.render(**template_data)
        # Write to file or return
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logging.info(f"[$] Report generated: {output_file}")
        else:
            return html_content

    def generate_from_file(self, json_file, output_file=None, template_path=None):
        """Generate report from JSON file"""
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                scan_data = json.load(f)
            if not output_file:
                output_file = json_file.replace('.json', '_report.html')
            # Use custom template if provided
            if template_path:
                self.__init__(template_path=template_path)
            return self.generate_report(scan_data, output_file)
        except FileNotFoundError:
            print(f"Error: File '{json_file}' not found.")
            return None
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in '{json_file}': {e}")
            return None
        except Exception as e:
            print(f"Error generating report: {e}")
            return None