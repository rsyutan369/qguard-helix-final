const fs = require('fs');
const file = 'src/app/dashboard/page.tsx';
let c = fs.readFileSync(file, 'utf8');
c = c.replace(/\r\n/g, '\n');

const oldChunk2 = `        {/* Sidebar Insights */}
        <aside className="space-y-8">
          <RecommendationsPanel summary={summary} loading={loading} />
          
          {/* Quick Actions / Status */}
          <div className={\`p-6 \${GLASS_PANEL_CLASSES}\`}>
            <div className="absolute -right-4 -bottom-4 opacity-5">
                <Shield className="w-32 h-32 text-gold" />
            </div>
            <h2 className="text-sm font-black uppercase tracking-[0.2em] text-white/80 mb-4">System Integrity</h2>
            <div className="space-y-4 relative z-10">
                <div className="flex items-center justify-between">
                    <span className="text-[10px] font-bold text-white/40 uppercase">PQC Engine</span>
                    <span className="text-[10px] font-black text-green-500 uppercase flex items-center gap-1.5">
                        <div className="w-1.5 h-1.5 bg-green-500 rounded-full" /> Optimal
                    </span>
                </div>
                <div className="flex items-center justify-between">
                    <span className="text-[10px] font-bold text-white/40 uppercase">QRNG Entropy</span>
                    <span className="text-[10px] font-black text-green-500 uppercase flex items-center gap-1.5">
                        <div className="w-1.5 h-1.5 bg-green-500 rounded-full" /> 256-bit
                    </span>
                </div>
                <div className="flex items-center justify-between">
                    <span className="text-[10px] font-bold text-white/40 uppercase">Real-time Hook</span>
                    <span className="text-[10px] font-black text-gold uppercase flex items-center gap-1.5">
                        Connected
                    </span>
                </div>
                <div className="pt-4 mt-4 border-t border-white/5">
                    <button className="w-full py-2 bg-white/5 border border-white/10 text-[10px] font-black uppercase tracking-widest text-white/60 rounded hover:bg-white/10 transition-colors">
                        Download Compliance Report
                    </button>
                </div>
            </div>
          </div>
        </aside>`;

const newChunk2 = `        {/* Sidebar Insights */}
        <aside className="space-y-8">
          {/* Real-time Events */}
          <section className="space-y-4 h-[450px]">
            <SecurityEventsPanel events={events} loading={loading} />
          </section>
        </aside>`;

c = c.replace(oldChunk2, newChunk2);

fs.writeFileSync(file, c);
console.log('done');
