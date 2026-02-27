import gradio as gr
from typing import List

def make_ui(manager, binary_path):
    # simple dashboard showing instances and controls
    def list_instances():
        items = manager.list_instances()
        if not items:
            return "No instances"
        out = []
        for k,v in items.items():
            out.append(f"{k} — {v['status']} — {v['config']}")
        return "\n".join(out)

    def create_instance(instance_id, local_port, remote_port, server_addr):
        # create a minimal toml config in configs
        import os, toml
        cfg = {
            'common': {
                'server_addr': server_addr,
                'server_port': int(remote_port)
            }
        }
        path = os.path.join('configs', f"{instance_id}.toml")
        with open(path, 'w') as f:
            toml.dump(cfg, f)
        manager.create_instance(instance_id, path)
        return f"Created {instance_id}"

    def start_instance(instance_id):
        manager.start_instance(instance_id, binary_path)
        return f"Started {instance_id}"

    def stop_instance(instance_id):
        manager.stop_instance(instance_id)
        return f"Stopped {instance_id}"

    with gr.Blocks() as demo:
        gr.Markdown('# FRP Wrapper Dashboard')
        with gr.Row():
            inst_list = gr.Textbox(value='No instances', lines=10)
            with gr.Column():
                refresh = gr.Button('Refresh')
                id_in = gr.Textbox(label='Instance ID')
                server_addr = gr.Textbox(label='Server Addr', value='127.0.0.1')
                server_port = gr.Textbox(label='Server Port', value='7000')
                create_btn = gr.Button('Create')
                start_btn = gr.Button('Start')
                stop_btn = gr.Button('Stop')
        refresh.click(fn=lambda: list_instances(), outputs=inst_list)
        create_btn.click(fn=create_instance, inputs=[id_in, '1', server_port, server_addr], outputs=inst_list)
        start_btn.click(fn=start_instance, inputs=[id_in], outputs=inst_list)
        stop_btn.click(fn=stop_instance, inputs=[id_in], outputs=inst_list)

    return demo
