from django import forms

class PunchplusplusConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'

    url = forms.CharField(required=True,
                           label="URL",
                           initial='https://packetmail.net/',
                           widget=forms.TextInput(),
                           help_text="URL for Punch++ Service")
    url_dump = forms.CharField(required=True,
                           label="CheckMyDump URL",
                           initial='https://checkmydump.miscreantpunchers.net/',
                           widget=forms.TextInput(),
                           help_text="URL for CheckMyDump Service")

    apiKey = forms.CharField(required=True,
                               label="API Key",
                               initial='',
                               widget=forms.TextInput(),
                               help_text="API Key")

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(PunchplusplusConfigForm, self).__init__(*args, **kwargs)
