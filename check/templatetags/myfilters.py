from django import template

register = template.Library()

@register.filter(name='check_score')
def check_score(value):
    li = value.split('/')
    score = int(li[0])
    total = int(li[1])
    if score > 5 and score < total:
        return True
    else:
        return False

@register.filter(name='ifinlist')
def ifinlist(value, list):
    li = []
    if list != 'No Info':
        try:
            val = int(value)
            for i in list.split(','):
                li.append(int(i.strip()))
            return True if val in li else False
        except:
            return True
    elif list == 'No Info':
        return False

@register.filter(name='is_mal')
def is_mal(value):
    return True if value == 'Poor' else False

@register.filter(name='is_len')
def is_len(value):
    try:
        if len(value) > 0:
            return True
        else:
            return False
    except Exception as e:
        print(e)

@register.filter(name='is_risk')
def is_risk(value):
    if value == 'high':
        return True
    else:
        return False

@register.filter(name='replace')
def replace(value, data):
    return value.replace(data, '')

