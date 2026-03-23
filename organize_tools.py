import os
import shutil
from pathlib import Path

def main():
    base_dir = Path(r"C:\Users\CyberOps\Desktop\DOOM-SEC")
    ignored_dirs = {'.venv', '.git'}
    ignored_files = {'README.md', 'LICENSE', 'requirements.txt', '.gitignore', 'organize_tools.py'}
    
    # Tool info: base_name -> {'payload': Path, 'post': Path}
    tools = {}
    
    # 1. Discover all files
    for root, dirs, files in os.walk(base_dir):
        # Exclude ignored dirs
        dirs[:] = [d for d in dirs if d not in ignored_dirs and not d.startswith('.')]
        for file in files:
            if file in ignored_files:
                continue
            
            p = Path(root) / file
            name = file
            stem = p.stem
            
            if name.endswith("_Post.txt") or name.lower() == "post.txt":
                # It's a post file
                if name.lower() == "post.txt":
                    base_name = p.parent.name
                else:    
                    base_name = name[:name.rfind("_Post.txt")]
                
                if base_name not in tools:
                    tools[base_name] = {'payload': None, 'post': None}
                tools[base_name]['post'] = p
            else:
                # Assuming it's a payload file
                base_name = stem
                if base_name not in tools:
                    tools[base_name] = {'payload': None, 'post': None}
                tools[base_name]['payload'] = p
                
    # 2. Process each tool
    for base_name, info in tools.items():
        payload_p = info['payload']
        post_p = info['post']
        
        # Decide target directory
        if payload_p:
            target_parent = payload_p.parent
        elif post_p:
            target_parent = post_p.parent
        else:
            continue
            
        target_dir = target_parent / base_name
        target_dir.mkdir(parents=True, exist_ok=True)
        
        # Move or create payload
        if payload_p:
            if payload_p.parent != target_dir: # prevent moving if already there
                new_payload_p = target_dir / payload_p.name
                shutil.move(str(payload_p), str(new_payload_p))
        else:
            # Create dummy payload
            new_payload_p = target_dir / f"{base_name}.py"
            new_payload_p.write_text("# Auto-generated dummy payload\n")
            
        # Move or create post file
        if post_p:
            if post_p.parent != target_dir:
                new_post_p = target_dir / f"{base_name}_Post.txt"
                shutil.move(str(post_p), str(new_post_p))
        else:
            # Create dummy post file
            new_post_p = target_dir / f"{base_name}_Post.txt"
            new_post_p.write_text("Auto-generated post execution notes\n")
            
    print(f"Organized {len(tools)} tools.")

if __name__ == "__main__":
    main()
