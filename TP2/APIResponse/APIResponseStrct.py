import json

def format_api_response(api_response):
    try:
        data = api_response['data']
        attributes = data['attributes']

        # Check if 'file_info' exists before using it
        if 'file_info' not in attributes:
            print("Warning: 'file_info' not found in attributes")
            file_info = {}
        else:
            file_info = attributes['file_info']

        # Proceed with other processing as usual
        analysis_results = attributes['analysis_results']
        engines_results = attributes['engines_results']
        links = data['links']

        message = ""

        message += f"**API Response Summary**\n\n"
        message += f"**Request ID**: {data['id']}\n"
        message += f"**Type**: {data['type']}\n"

        message += f"\n**File Information**:\n"
        if file_info:
            message += f"- **SHA-256**: {file_info.get('sha256', 'N/A')}\n"
            message += f"- **File Size**: {file_info.get('file_size', 'N/A')} bytes\n"
            message += f"- **MD5**: {file_info.get('md5', 'N/A')}\n"
            message += f"- **SHA-1**: {file_info.get('sha1', 'N/A')}\n"
        else:
            message += "- No file information available.\n"

        message += f"\n**Analysis Results**:\n"
        message += f"- **Malicious**: {analysis_results['malicious']} engines flagged as malicious.\n"
        message += f"- **Suspicious**: {analysis_results['suspicious']} engines flagged as suspicious.\n"
        message += f"- **Undetected**: {analysis_results['undetected']} engines detected no issues.\n"
        message += f"- **Harmless**: {analysis_results['harmless']} engines flagged as harmless.\n"
        message += f"- **Timeout**: {analysis_results['timeout']} engines failed to analyze.\n"
        message += f"- **Unsupported**: {analysis_results['unsupported']} engines don’t support this file.\n"

        message += f"\n**Engines Results**:\n"
        for engine_result in engines_results:
            message += f"- **Engine**: {engine_result['engine']} | **Result**: {engine_result['result']}\n"

        message += f"\n**VirusTotal Links**:\n"
        message += f"- **Analysis Link**: [View detailed analysis report]({links['analysis']})\n"
        message += f"- **File Details**: [View file information]({links['file']})\n"

        return message
    except Exception as e:
        print(f"Error: {e}")
        return "An error occurred while processing the API response."

def main():
    # Define the file path assuming it's in the same directory as the script
    file_path = './HashResponse.txt'

    try:
        # Read the text file and treat its contents as JSON string
        with open(file_path, 'r') as file:
            file_content = file.read()

        # Parse the content as JSON
        api_response = json.loads(file_content)

        # Print the structure of the loaded API response for debugging
        print(json.dumps(api_response, indent=4))  # Pretty print the JSON structure

        # Format the API response
        formatted_message = format_api_response(api_response)

        # Output the formatted message (you can print it or save it to a new file)
        print(formatted_message)

        # Optionally, save the formatted message to a new file
        with open('formatted_response.txt', 'w') as output_file:
            output_file.write(formatted_message)

    except FileNotFoundError:
        print(f"Error: The file at {file_path} was not found.")
    except json.JSONDecodeError:
        print("Error: The file content is not a valid JSON string.")

if __name__ == "__main__":
    main()
