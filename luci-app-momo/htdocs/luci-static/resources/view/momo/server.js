'use strict';
'require view';

// Embed the PassWall 2 Server-Side manager (servers / users) inside the Momo menu,
// reusing the existing passwall2_server backend and CBI pages.
return view.extend({
    render: function () {
        const frame = E('iframe', {
            src: L.url('admin', 'services', 'passwall2', 'server'),
            style: 'width: 100%; height: calc(100vh - 175px); min-height: 500px; border: none; border-radius: 3px;'
        });
        return E([], [frame]);
    },
    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
