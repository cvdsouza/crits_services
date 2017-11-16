from django import forms

class IntelConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'

    base_url = forms.CharField(required=False,
                           label="URL",
                           initial='https://xyz.net/',
                           widget=forms.TextInput(),
                           help_text="Web URL to post the Intel to")

    org_name = forms.CharField(required=True,
                             label="Org Name",
                             initial='',
                             widget=forms.TextInput(),
                             help_text="Organization Name")

    api_email = forms.CharField(required=True,
                               label="User Email",
                               initial='',
                               widget=forms.TextInput(),
                               help_text="User Email")

    api_password = forms.CharField(required=True,
                                label="Password",
                                initial='',
                                widget=forms.PasswordInput(),
                                help_text="Password")


    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(IntelConfigForm, self).__init__(*args, **kwargs)

class IntelRunForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'

    ticketNumber = forms.IntegerField(required=True,
                                   label="Ticket Number",
                                   initial='',
                                   #widget=forms.TextInput(),
                                   help_text="Ticket Number")

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(IntelRunForm, self).__init__(*args, **kwargs)
