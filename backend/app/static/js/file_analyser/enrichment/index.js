var Enrichment = {
    set_events: () => {
        let enrichment_virus_shares = document.getElementById('enrichment_virus_shares');
        if (enrichment_virus_shares != undefined)
            document.getElementById('enrichment_virus_shares').addEventListener('click', Enrichment.virus_shares)
        
        setInterval(Enrichment.virus_shares_check, 10000);
    },

    virus_shares: (evt) => {
        fetch('/file_analyser/enrichment/virus_shares/', {
            method: "POST",
        })
        .then(res => {
            if (res.status != 200) {
                console.warn(res);
                $.SOW.core.toast.show('danger', 'Ошибка', 'Что-то пошло не так...', 'top-right', 3000, true)
                return;
            }

            if (res.redirected) {
                window.location.href = res.url
                return;
            }

            return res.json()
        }, err => console.error(err))
        .then(json => {
            if (json.status == "fail")
                $.SOW.core.toast.show('danger', 'Ошибка', json.text, 'top-right', 3000, true)
        })
        .catch(warn => console.warn(warn))
    },

    virus_shares_check: () => {
        console.log("CHECK")
        fetch('/file_analyser/enrichment/virus_shares/check/', {
            method: "POST",
        })
        .then(res => {
            if (res.status != 200) {
                console.warn(res);
                $.SOW.core.toast.show('danger', 'Ошибка', 'Что-то пошло не так...', 'top-right', 3000, true)
                return;
            }

            if (res.redirected) {
                window.location.href = res.url
                return;
            }

            return res.json()
        }, err => console.error(err))
        .then(json => {
            if (json.status == "fail")
                $.SOW.core.toast.show('danger', 'Ошибка', json.text, 'top-right', 3000, true)
            
            Object.keys(json).forEach(task_id => {
                // console.log(task_id)
                document.getElementById(task_id).textContent = json[task_id]
            })
        })
        .catch(warn => console.warn(warn))
    },
}

Enrichment.set_events()