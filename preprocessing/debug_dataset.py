import os
from pathlib import Path

# بررسی مسیرها و فایل‌ها
def check_directories():
    print("=== بررسی مسیرها ===\n")
    
    # مسیرهای اصلی
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
            print("✓ مسیر وجود دارد")
            
            # شمارش فایل‌ها و پوشه‌ها
            files = list(Path(path).iterdir())
            sol_files = list(Path(path).glob("*.sol"))
            directories = [f for f in files if f.is_dir()]
            
            print(f"  - تعداد کل آیتم‌ها: {len(files)}")
            print(f"  - تعداد فایل‌های .sol: {len(sol_files)}")
            print(f"  - تعداد پوشه‌ها: {len(directories)}")
            
            # نمایش چند نمونه
            if files:
                print("  - نمونه آیتم‌ها:")
                for i, f in enumerate(files[:5]):
                    print(f"    {i+1}. {f.name} {'(پوشه)' if f.is_dir() else ''}")
                if len(files) > 5:
                    print(f"    ... و {len(files)-5} مورد دیگر")
        else:
            print("✗ مسیر وجود ندارد!")

if __name__ == "__main__":
    check_directories()