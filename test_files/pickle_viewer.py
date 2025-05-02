# inspect_pickle.py

import pickle

def inspect_pickle(file_path):
    '''
    Load and inspect the content of a pickle file.
    '''
    try:
        with open(file_path, 'rb') as file:
            obj = pickle.load(file)
            print(f"\nSuccessfully loaded: {file_path}")
            print(f"Type of object: {type(obj)}")
            
            if isinstance(obj, dict):
                print(f"Keys: {list(obj.keys())[:10]}")
            elif isinstance(obj, list):
                print(f"List length: {len(obj)}")
                print(f"First item type: {type(obj[0]) if obj else 'Empty list'}")
            elif hasattr(obj, 'predict'):
                print(f"Looks like a model object (has .predict method). Ready to predict!")
            elif hasattr(obj, 'head'):
                # If it has a head() method, it’s probably a DataFrame
                print("Preview of DataFrame:")
                print(obj.head())
            else:
                print(f"Object content preview: {str(obj)[:500]}...")  # Print first 500 chars
    except Exception as e:
        print(f"Failed to load {file_path}: {e}")

# --- MAIN ---

# Path to your pickle file
pickle_file_path = 'network_anomoly_model_mb_es.pkl'

inspect_pickle(pickle_file_path)
