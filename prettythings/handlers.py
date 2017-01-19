from crits.campaigns.campaign import Campaign
from crits.events.event import Event
from crits.emails.email import Email

def campaign_heatmap(request):
    campaigns = Campaign.objects().only('name', 'aliases', 'locations')
    events = Event.objects().only('title', 'created', 'locations', 'campaign')
    emails = Email.objects().only('created', 'locations', 'campaign')

    # list of countries in alphabetical order
    country_list = []
    for c in campaigns:
        if len(c.locations):
            for l in c.locations:
                if [l.location,0] not in country_list:
                    country_list.append([l.location,0])
    country_list.sort()

    # list of campaigns in order of country, then alphabetical by name
    campaign_list = []
    # for each country we build a tmp list, find all campaigns for that country,
    # sort the list, then append it to the campaign list
    for c in country_list:
        tmp = []
        for cam in campaigns:
            if len(cam.locations):
                for l in cam.locations:
                    if l.location == c[0]:
                        c[1] += 1
                        if cam.name not in tmp:
                            tmp.append(cam.name)
                        break
        tmp.sort()
        campaign_list += tmp

    # list of the months going back in history and the activity of each campaign
    # during that month
    month_list = []
    # for each campaign, find associated events and emails. For each event and
    # email, use the created date to put it into the appropriate list.
    month_d = {}
    idx = 0
    pad_list = [0 for _ in range(len(campaign_list))]
    for c in campaign_list:
        build_month_d(pad_list, month_d, c, idx, events)
        build_month_d(pad_list, month_d, c, idx, emails)
        idx += 1

    for key in sorted(month_d, reverse=True):
        month_list.append([key, month_d[key]])

    # list of the grand total of activity for a given campaign
    grand_total_list = []

    final_data = {
        'country_list': country_list,
        'campaign_list': campaign_list,
        'grand_total_list': grand_total_list,
        'month_list': month_list,
    }

    return final_data

def build_month_d(pad_list, month_d, campaign, idx, elist):
    for e in elist:
        created = e.created.strftime("%Y-%m")
        if not month_d.get(created, None):
            month_d[created] = list(pad_list)
        if len(e.campaign):
            for cam in e.campaign:
                if cam.name == campaign:
                    month_d[created][idx] += 1
