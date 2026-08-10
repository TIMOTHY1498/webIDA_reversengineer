import * as Format from './index_format.ts';
import NtExecutable, {
	NtExecutableFromOptions,
	NtExecutableSection,
} from './NtExecutable.ts';
import NtExecutableResource from './NtExecutableResource.ts';
import { calculateCheckSumForPE } from './functions.ts';
import * as Type from './index_type.ts';

function convertBinaryString(bin_str) {
	return Uint8Array.from(bin_str, (c) => c.charCodeAt(0)).buffer;
}

function loadPEFIle(arr_buff) {
	let exe_info = NtExecutable.from(arr_buff);

	return {
		dosHeader: exe_info.dosHeader(),
		ntHeaders: exe_info.ntHeaders(),
		sections: exe_info.sections(),
		resources: exe_info.resources(),
		exportDirectory: exe_info.exportDirectory(),
		importDirectory: exe_info.importDirectory(),
		exportTable: exe_info.exportTable(),
		importTable: exe_info.importTable(),
		tlsTable: exe_info.tlsTable(),
		loadConfig: exe_info.loadConfig(),
		resourceTable: exe_info.resourceTable(),
		overlay: exe_info.overlay(),
	};
}

function Main(bin_PE) {
	let arr_buff = convertBinaryString(bin_PE);
	let loaded_PE = loadPEFIle(arr_buff);

	console.log(loaded_PE);
	return loaded_PE;
}

window.addEventListener('DOMContentLoaded', () => {
	const testInput = document.querySelector('#testInput');
	testInput.addEventListener('change', (event) => {
		const file = event.target.files[0];
		if (!file) {
			return;
		}

		const reader = new FileReader();
		reader.onload = (e) => {
			const data = e.target.result;
			Main(data);
		};
		reader.readAsBinaryString(file);
	});
});
