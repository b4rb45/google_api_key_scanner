import requests
from colorama import init, Fore, Style
import argparse

init(autoreset=True)

def print_banner():
    print(Fore.CYAN + Style.BRIGHT + r"""
╔════════════════════════════════════════════════════════════════╗
║            🔍 Google API Key Security Checker - 0D1N           ║
║      Hecho en Chile con pica, café y fuzzing pa' rato ☕️💥     ║
╚════════════════════════════════════════════════════════════════╝
""" + Style.RESET_ALL)
    print(Fore.YELLOW + "🚨 Detecta claves inseguras que podrían costar 💸 a lo tonto\n")

def test_api(name, url, params):
    print(Fore.CYAN + f"[*] Probando {name} API...")
    try:
        response = requests.get(url, params=params, timeout=10)
        data = response.json()

        if data.get("status") == "OK":
            print(Fore.GREEN + f"[+] {name} API FUNCIONA ✅ => ¡Potencial abuso económico!\n")
        elif data.get("status") in ["REQUEST_DENIED", "OVER_QUERY_LIMIT", "INVALID_REQUEST"]:
            print(Fore.RED + f"[!] {name} API RESTRINGIDA 🚫 => {data.get('error_message', 'Sin detalle')}\n")
        else:
            print(Fore.YELLOW + f"[?] {name} API Respuesta inesperada 🧐 => {data.get('status')}\n")
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[!] Error HTTP al probar {name} API: {str(e)}\n")
    except ValueError:
        print(Fore.RED + f"[!] La respuesta de {name} no es JSON válido.\n")
    except Exception as e:
        print(Fore.RED + f"[!] Error al probar {name} API: {str(e)}\n")

def get_args():
    parser = argparse.ArgumentParser(description="Validador de API Key de Google para múltiples servicios.")
    parser.add_argument("-k", "--key", required=True, help="API Key de Google a evaluar")
    return parser.parse_args()

if __name__ == "__main__":
    print_banner()
    args = get_args()
    api_key = args.key.strip()

    if not api_key:
        print(Fore.RED + "❌ No se ingresó ninguna API key. Abortando.")
        exit()

    services = [
        {"name": "Geocoding", "url": "https://maps.googleapis.com/maps/api/geocode/json",
         "params": {"address": "Santiago, Chile", "key": api_key}},

        {"name": "Places", "url": "https://maps.googleapis.com/maps/api/place/textsearch/json",
         "params": {"query": "restaurants in Santiago", "key": api_key}},

        {"name": "Directions", "url": "https://maps.googleapis.com/maps/api/directions/json",
         "params": {"origin": "Santiago", "destination": "Valparaiso", "key": api_key}},

        {"name": "Distance Matrix", "url": "https://maps.googleapis.com/maps/api/distancematrix/json",
         "params": {"origins": "Santiago", "destinations": "Valparaiso", "key": api_key}},

        {"name": "Timezone", "url": "https://maps.googleapis.com/maps/api/timezone/json",
         "params": {"location": "-33.4489,-70.6693", "timestamp": "1331161200", "key": api_key}},

        {"name": "Static Maps", "url": "https://maps.googleapis.com/maps/api/staticmap",
         "params": {"center": "Santiago", "zoom": "13", "size": "600x300", "maptype": "roadmap", "key": api_key}},

        {"name": "Elevation", "url": "https://maps.googleapis.com/maps/api/elevation/json",
         "params": {"locations": "36.578581,-118.291994", "key": api_key}},

        {"name": "Street View", "url": "https://maps.googleapis.com/maps/api/streetview/metadata",
         "params": {"location": "Santiago", "key": api_key}},

        {"name": "Autocomplete", "url": "https://maps.googleapis.com/maps/api/place/autocomplete/json",
         "params": {"input": "restaurante", "key": api_key}},

        {"name": "Geolocation", "url": "https://www.googleapis.com/geolocation/v1/geolocate",
         "params": {"key": api_key}},

        {"name": "Roads", "url": "https://roads.googleapis.com/v1/snapToRoads",
         "params": {"path": "60.170880,24.942795|60.170879,24.942796", "interpolate": "true", "key": api_key}}
    ]

    for service in services:
        test_api(service["name"], service["url"], service["params"])

    print(Fore.CYAN + Style.BRIGHT + "\n🏁 Fin de la evaluación. Si alguna API está expuesta, ¡repórtala como dios del bug bounty! 🤑")
