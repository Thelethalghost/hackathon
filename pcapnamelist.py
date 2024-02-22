import os

# Specify the directory path
folder_path = 'VIT_Hackathon_Sample_Pcaps'

# List all files in the folder
file_names = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]

print(sorted(file_names))
