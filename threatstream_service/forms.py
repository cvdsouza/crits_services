from django import forms

class ThreatStreamConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'

    url = forms.CharField(required=True,
                           label="URL",
                           initial='https://threatstream.com/api/v1/',
                           widget=forms.TextInput(),
                           help_text="URL for Anomali ThreatStream Service")

    user_email = forms.CharField(required=True,
                          label="User Email",
                          initial='abc@xyz.com',
                          widget=forms.TextInput(),
                          help_text="Email for Anomali ThreatStream Service")

    apiKey = forms.CharField(required=True,
                               label="API Key",
                               initial='',
                               widget=forms.TextInput(),
                               help_text="API Key")

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(ThreatStreamConfigForm, self).__init__(*args, **kwargs)
