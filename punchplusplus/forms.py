from django import forms

class PunchplusplusConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'

    url = forms.CharField(required=True,
                           label="URL",
                           initial='https://packetmail.net/',
                           widget=forms.TextInput(),
                           help_text="URL for Punch++ Service")

    apiKey = forms.CharField(required=True,
                               label="API Key",
                               initial='',
                               widget=forms.TextInput(),
                               help_text="API Key")

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(PunchplusplusConfigForm, self).__init__(*args, **kwargs)


class PunchplusplusRunForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'

    def __init__(self, url=None, apiKey=None, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(PunchplusplusRunForm, self).__init__(*args, **kwargs)

        if url and apiKey :

            self.fields['ip_rep'] = forms.BooleanField(required=False,
                                                            initial=False,
                                                            label="IP Rep",
                                                            help_text="Performs reputation check on IP Addresses")

            self.fields['pcre_match'] = forms.BooleanField(required=False,
                                                            initial=False,
                                                            label="PCRE",
                                                            help_text="PCRE for full url match")
