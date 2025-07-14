import os
from pathlib import Path

def check_directories():
    print("=== Directory Check ===\n")
    
    paths_to_check = {
        "Vulnerable contracts source": r"C:\Users\Hadis\Documents\bad_randomness_main\comprehensive_analysis\vulnerable_contracts",
        "Safe contracts source": r"C:\Users\Hadis\Documents\bad_randomness_main\comprehensive_analysis\safe_contracts",
        "Batch1 vulnerable": r"C:\Users\Hadis\Documents\NewModel1\batch1\vulnerable1",
        "Batch1 safe": r"C:\Users\Hadis\Documents\NewModel1\batch1\safe1",
        "Batch2 vulnerable": r"C:\Users\Hadis\Documents\NewModel1\batch2\vulnerable2",
        "Batch2 safe": r"C:\Users\Hadis\Documents\NewModel1\batch2\safe2"
    }
    
    for name, path in paths_to_check.items():
        print(f"\n{name}:")
        print(f"Path: {path}")
        
        if Path(path).exists():
            print("✓ Path exists")
            
            files = list(Path(path).iterdir())
            sol_files = list(Path(path).glob("*.sol"))
            directories = [f for f in files if f.is_dir()]
            
            print(f"  - Total items: {len(files)}")
            print(f"  - .sol files: {len(sol_files)}")
            print(f"  - Directories: {len(directories)}")
            
            if files:
                print("  - Sample items:")
                for i, f in enumerate(files[:5]):
                    print(f"    {i+1}. {f.name} {'(directory)' if f.is_dir() else ''}")
                if len(files) > 5:
                    print(f"    ... and {len(files)-5} more")
        else:
            print("✗ Path does not exist!")

if __name__ == "__main__":
    check_directories()
