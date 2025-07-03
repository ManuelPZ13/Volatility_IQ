import os
import configparser
import yara
import yaml

SETTINGS_FILE = 'settings.ini'

def cargar_config():
    config = configparser.ConfigParser()
    if not os.path.exists(SETTINGS_FILE):
        config['GENERAL'] = {
            'yara_rules': 'rules.yar',
            'ioc_yaml': 'ioc_playbook.yaml'
        }
        with open(SETTINGS_FILE, 'w') as f:
            config.write(f)
    else:
        config.read(SETTINGS_FILE)
        if 'GENERAL' not in config.sections():
            config['GENERAL'] = {
                'yara_rules': 'rules.yar',
                'ioc_yaml': 'ioc_playbook.yaml'
            }
            with open(SETTINGS_FILE, 'w') as f:
                config.write(f)
    return config

def cargar_yara_rules(ruta):
    if os.path.exists(ruta):
        try:
            return yara.compile(filepath=ruta)
        except yara.Error as e:
            print(f"Error compilando reglas YARA: {e}")
            return None
    return None

def cargar_ioc_yaml(ruta):
    if os.path.exists(ruta):
        with open(ruta, "r") as f:
            return yaml.safe_load(f)
    return {}
