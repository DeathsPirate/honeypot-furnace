import json

def convert_datetime(datetime_str):
    date_part, time_part = datetime_str.split(' ')
    hms, ms = time_part[0:8], time_part.split(':')[3] 
    timestamp = date_part + 'T' + hms + '.' + ms
    return timestamp


async def processEvent(event):
    # Make sure we have a dict object to work with first
    if not type(event) is dict:
        event = json.loads(event)

    # Extract out the message object from the event (we aren't interested in the outer wrapper)
    message = event['message']
    # Convert the message string into a json object 
    message = json.loads(message)

    # Extract the attacker IP into it's own field
    message['srcaddr'] = message['containerName'].split('-')[1]

    if message['type'] == 'spyusers':
        message['baseCommand'] = message['command']
        del message['command']
        
    if message['type'] == 'stdin':
        message['fullCommand'] = message['command']
        del message['command']

    message['@timestamp'] = convert_datetime(message['datetime'])
    
    return message

