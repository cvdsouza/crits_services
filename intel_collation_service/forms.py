from django import forms

class IntelConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'

    url = forms.CharField(required=False,
                           label="URL",
                           initial='https://xyz.net/',
                           widget=forms.TextInput(),
                           help_text="Web URL to post the Intel to")

    apiKey = forms.CharField(required=False,
                               label="API Key",
                               initial='',
                               widget=forms.TextInput(),
                               help_text="API Key")

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(IntelConfigForm, self).__init__(*args, **kwargs)