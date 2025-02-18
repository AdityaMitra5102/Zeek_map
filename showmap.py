file='/opt/zeek/logs/current/conn.log' #Change it to the zeek folder conn.log path. Ensure it has read permissions
location_bkp='loc.json' #Just point it to a writeable location. This is used to backup ip locations so as not to overuse the API


from flask import *
import json
from zat import zeek_log_reader
import requests
import time
import ipaddress
location_backup={}
def read_backup():
	global location_backup
	try:
		with open(location_bkp, 'r') as f:
			location_backup=json.load(f)
	except:
		pass

read_backup()

def save_backup():
	global location_backup
	try:
		with open(location_bkp, 'w') as f:
			json.dump(location_backup, f, indent=4)
	except:
		pass

def read_logs():
	reader = zeek_log_reader.ZeekLogReader(file)
	loglist=[]
	for row in reader.readrows():
		loglist.append(row)
	return loglist
	
def to_string(log_item):
	ts=log_item.get('ts').isoformat(' ')
	orig=f'{log_item["id.orig_h"]}:{log_item["id.orig_p"]}'
	dest=f'{log_item["id.resp_h"]}:{log_item["id.resp_p"]}'
	service=f'{log_item["proto"]}:{log_item["service"]}'.upper()
	text=f'''Timestamp: {ts}
	Source {orig}
	Destination {dest}
	Service {service}'''
	return text

def get_geo_coords(ip):
	if ip in location_backup:
		return location_backup[ip]
	api=f'http://ip-api.com/json/{ip}'
	resp=requests.get(api).json()
	time.sleep(0.8) #Delay to prevent rate limitting
	location_backup[ip]=resp
	save_backup()
	return location_backup[ip]
	
def get_geo_text(ip):
	details=get_geo_coords(ip)
	if details['status'] != 'success':
		return ''
	text=f'Location: {details["city"]}, {details["regionName"]}, {details["country"]}'
	return text
	
def is_ip_plottable(ip):
	try:
		ip_obj=ipaddress.ip_address(ip)
		if not isinstance(ip_obj, ipaddress.IPv4Address):
			return False
		return ip_obj.is_global
	except:
		return False
		
def get_single_map_elem(log_item, ip):
	logtext=to_string(log_item)
	if is_ip_plottable(ip):
		ip_details=get_geo_coords(ip)
		if ip_details['status'] != 'success':
			return None
		point={}
		point['type']='Feature'
		point['properties']={}
		point['properties']['popupContent']=logtext+'\n'+get_geo_text(ip)
		point['properties']['popupContent']=point['properties']['popupContent'].replace('\n', '\n<br>')
		
		point['geometry']={}
		point['geometry']['type']='Point'
		point['geometry']['coordinates']=[ip_details['lon'], ip_details['lat']]
		return point
	return None

		
def get_map_elem(log_item):
	elems=[]
	ip=log_item['id.orig_h']
	ip_pt=get_single_map_elem(log_item, ip)
	if ip_pt is not None:
		elems.append(ip_pt)
	ip=log_item['id.resp_h']
	ip_pt=get_single_map_elem(log_item, ip)
	if ip_pt is not None:
		elems.append(ip_pt)
	return elems
	
def get_all_points():
	logs=read_logs()
	featlist=[]
	for log in logs:
		temp=get_map_elem(log)
		for x in temp:
			featlist.append(x)
	featcollec={}
	featcollec['type']='FeatureCollection'
	featcollec['features']=featlist
	return featcollec
	
def gen_html():
	html='''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zeek Map</title>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <style>
        html, body {
            margin: 0;
            padding: 0;
            height: 100%;
        }
        #map {
            width: 100%;
            height: 100vh;
        }
    </style>
</head>
<body>
    <div id="map"></div>
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <script>
        const map = L.map('map', {
            zoomControl: true
        }).setView([0, 0], 3);

        const streetLayer = L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '&copy; OpenStreetMap contributors'
        });

        const satelliteLayer = L.tileLayer('https://{s}.tile.opentopomap.org/{z}/{x}/{y}.png', {
            attribution: '&copy; OpenTopoMap contributors'
        });

        const baseMaps = {
            "Street View": streetLayer,
            "Satellite View": satelliteLayer
        };

        streetLayer.addTo(map);

        L.control.layers(baseMaps).addTo(map);

        const geojsonData = $$geojsondata$$;

        const geojsonLayer = L.geoJSON(geojsonData, {
            onEachFeature: function (feature, layer) {
                if (feature.properties && feature.properties.popupContent) {
                    layer.bindPopup(feature.properties.popupContent);
                    layer.on('mouseover', function () {
                        this.openPopup();
                    });
                    layer.on('mouseout', function () {
                        this.closePopup();
                    });
                }
            }
        }).addTo(map);
    </script>
</body>
</html>
	'''
	geojson=json.dumps(get_all_points(), indent=4)
	html=html.replace('$$geojsondata$$', geojson)
	return html
	

app = Flask(__name__)
@app.route("/", methods=["GET", "POST"])
def show_map():
	html=gen_html()
	return render_template_string(html)
	
if __name__=='__main__':
	app.run(host='0.0.0.0', port=5000)