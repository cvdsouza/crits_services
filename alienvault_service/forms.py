from django import forms

class AlienVaultConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    av_url = forms.BooleanField(required=False,
                                            initial=False,
                                            label='AlienVault',
                                            help_text="https://otx.alienvault.com:443/api/v1/")
    av_api = forms.CharField(required=True,
                                 label="API Key",
                                 widget=forms.TextInput(),
                                 help_text="Obtain API key from OTX Alien Vault.",
                                 initial='')


    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(AlienVaultConfigForm, self).__init__(*args, **kwargs)